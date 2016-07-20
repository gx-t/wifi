#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

/*
Wifi card monitor mode set up:
https://sandilands.info/sgordon/capturing-wifi-in-monitor-mode-with-iw

Radiotap fields:
http://www.radiotap.org/defined-fields

Radiotap headers:
https://www.kernel.org/doc/Documentation/networking/radiotap-headers.txt

IEEE 802.11 frame format:
http://www.studioreti.it/slide/802-11-Frame_E_C.pdf

Wifibroadcast (Raspberry PI):
https://github.com/lwerdna/wifibroadcast

Good example for PF_PACKET:
https://github.com/openwrt/openwrt/tree/master/package/network/utils/iwcap

Socket filters:
https://www.kernel.org/doc/Documentation/networking/filter.txt
to generate filter program run tcpdump -dd ...
see tcpdump docs

-------------------------------------------------------------------------------

To prepare interface:
iw phy phy0 interface add mon0 type monitor
iw dev wlan0 del
ifconfig mon0 up
iw phy phy0 set channel 7
iw phy phy0 set txpower fixed 20
*/

enum {
	ERR_OK = 0,
	ERR_ARGC,
	ERR_ARGV,
	ERR_SOCKET,
	ERR_GETIFINDEX,
	ERR_GETSOCKFLAGS,
	ERR_SETSOCKFLAGS,
	ERR_BIND,
	ERR_ATTACHFILTER,
};

#define MAX_PACKET			0x400

//interface name
static const char* ifname = "wlan0-1";

//socket
static int ss = -1;

//radiotap headers + 802.11 frame
static const unsigned char rt_80211_headers[] = {
	//!!! CHANGING VALUES HERE NEED CHANGES IN gen-filter.sh !!!
	
	//----RADIOTAP HEADER----
	0x00, 0x00, // version and pad

	0x08, 0x00, // radiotap header length
	
	0x00, 0x00, 0x00, 0x00, // bitmap (field presense bits)

	//0x0c, 0x00, // len (12 bytes)
	//0x04, 0x80, 0x00, 0x00, // it_present bitmap (0x8004 is 1000 0000 0000 0100 is b15,b2)
	// b2==IEEE80211_RADIOTAP_RATE b15==IEEE80211_RADIOTAP_TX_FLAGS
	//0x22, // rate (in 500kb/s units), so 17Mb/s
	//0x0, // pad to get to 2-byte tx flag values
	//0x18, 0x00, // 0x18 is b4,b3 is F_FCS (fcs will removed and recalculated), F_FRAG (frame will be fragmented if beyond frag thr

	//----802.11 FRAME----
	0x08, 0x01, // type: data, subtype: 1
	0x00, 0x00, // duration: 0

	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // receiver/bssid: BROADCAST!
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // transmitter/source
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // destination

	0x10, 0x86, // frag/sequence
};


static int set_monitor()
{
	struct sockaddr_ll local = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL)
	};
	struct ifreq ifr;

	local.sll_ifindex = if_nametoindex(ifname);
	if(!local.sll_ifindex) {
		perror("if_nametoindex");
		return ERR_GETIFINDEX;
	}
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ss, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return ERR_GETSOCKFLAGS;
	}

	ifr.ifr_flags &= ~IFF_PROMISC;
	ifr.ifr_flags |=  IFF_BROADCAST;

	if (ioctl(ss, SIOCSIFFLAGS, &ifr)) {
		perror("SIOCGIFFLAGS");
		return ERR_SETSOCKFLAGS;
	}

	if(bind(ss, (struct sockaddr *)&local, sizeof(local)) == -1)
	{
		perror("bind");
		return ERR_BIND;
	}

	return ERR_OK;
}

static int init_socket() {
	ss = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(ss < 0) {
		perror("socket");
		return ERR_SOCKET;
	}
	return ERR_OK;
}

static void free_socket() {
	if(ss != -1) {
		close(ss);
		ss = -1;
	}
}

static int attach_filter() {

	static struct sock_filter code[] = {

		//run make filter to generate this file
#include "test00-filter.h"
	
	};

	struct sock_fprog bpf = {sizeof(code) / sizeof(code[0]), code};
	int lock = 1;

	if(setsockopt(ss, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0 ||
			setsockopt(ss, SOL_SOCKET, SO_LOCK_FILTER, &lock, sizeof(lock)) < 0)
	{
		perror("attach filter");
		return ERR_ATTACHFILTER;
	}

	return ERR_OK;
}

static void ctrl_c_rx(int sig) {
	fprintf(stderr, "\n");
	free_socket();
}

static int rx_main_loop() {
	signal(SIGINT, ctrl_c_rx);

	uint8_t buff[sizeof(rt_80211_headers) + 8 + MAX_PACKET];
	int len = 0;

	while(0 < (len = read(ss, buff, sizeof(buff)))) {

		//packet filtering is done in kernel - see gen-filter.sh
		uint8_t* pp = buff;
		uint16_t hlen = pp[2] | pp[3] << 8;

		pp += hlen; //jump to 802.11 frame

		//jump to payload
		pp += 24;

		//payload size
		len -= (pp - buff);

		//output data to stdout
		if(len != write(STDOUT_FILENO, pp, len)) break;
	}
	
	return ERR_OK;
}

static int rx_main() {
	int res = ERR_OK;
	
	(void)( (res = init_socket())
			|| (res = set_monitor())
			|| (res = attach_filter())
			|| (res = rx_main_loop()) );

	free_socket(ss);
	fprintf(stderr, ".end\n");
	return res;
}

static void ctrl_c_tx(int sig) {
	fprintf(stderr, "\n");
	close(0);
}

static int tx_main_loop() {
	signal(SIGINT, ctrl_c_tx);


	uint8_t buff[sizeof(rt_80211_headers) + MAX_PACKET];
	memcpy(buff, rt_80211_headers, sizeof(rt_80211_headers));

	int len = 0;

	while(0 < (len = read(STDIN_FILENO, buff + sizeof(rt_80211_headers), MAX_PACKET))) {

		len += sizeof(rt_80211_headers);
		if(len != write(ss, buff, len))
			break;
	}

	return ERR_OK;
}

static int tx_main() {
	int res = ERR_OK;
	
	(void)( (res = init_socket())
			|| (res = set_monitor())
			|| (res = tx_main_loop()) );

	free_socket(ss);
	fprintf(stderr, ".end\n");
	return res;
}

static int show_usage(const char* cmd, int err) {
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "-----------\n");
	fprintf(stderr, "%s rx       receive and write to stdout\n", cmd);
	fprintf(stderr, "%s tx       read stdin and broadcast\n", cmd);
	fprintf(stderr, "\nPacket size is %d bytes limited\n", MAX_PACKET);
	fprintf(stderr, "Logging information is written to stderr\n\n");
	return err;
}

int main(int argc, char* argv[]) {
	if(argc < 2) {
		fprintf(stderr, "\nArgument is missing\n");
		return show_usage(argv[0], ERR_ARGC);
	}

	if(!strcmp(argv[1], "rx"))
		return rx_main();
		
	if(!strcmp(argv[1], "tx"))
		return tx_main();

	fprintf(stderr, "\nUnknown subcommand: %s\n", argv[1]);
	return show_usage(argv[0], ERR_ARGV);
}

