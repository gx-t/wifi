#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/if_packet.h>

/*
Wifi card monitor mode set up:
https://sandilands.info/sgordon/capturing-wifi-in-monitor-mode-with-iw

Radiotap headers:
https://www.kernel.org/doc/Documentation/networking/radiotap-headers.txt

IEEE 802.11 frame format:
http://www.studioreti.it/slide/802-11-Frame_E_C.pdf

Wifibroadcast (Raspberry PI):
https://github.com/lwerdna/wifibroadcast

Good example for PF_PACKET:
https://github.com/openwrt/openwrt/tree/master/package/network/utils/iwcap

*/

#define MAX_PACKET			0x400

//socket
static int ss = -1;

//radiotap headers + 802.11 frame
static const unsigned char rt_80211_headers[] = {
	
	//----RADIOTAP HEADER----
	0x00, 0x00, // version and pad

	0x0c, 0x00, // radiotap header length
	//        0x08, 0x00, // radiotap header length
	0x04, 0x80, 0x00, 0x00, // bitmap (field presense bits)
	//		0x00, 0x00, 0x00, 0x00, // bitmap

	0x02, // rate in 500 kb/s units
	0x00, // pad

	0x18, // fragment control
	0x00, // pad

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

static int set_monitor(const char* ifname)
{
	struct sockaddr_ll local = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL)
	};
	struct ifreq ifr;

	local.sll_ifindex = if_nametoindex(ifname);
	if(!local.sll_ifindex) {
		perror("if_nametoindex");
		return 4;
	}
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if (ioctl(ss, SIOCGIFFLAGS, &ifr) < 0) {
		perror("SIOCGIFFLAGS");
		return 5;
	}

	ifr.ifr_flags &= ~IFF_PROMISC;
	ifr.ifr_flags |=  IFF_BROADCAST;

	if (ioctl(ss, SIOCSIFFLAGS, &ifr)) {
		perror("SIOCGIFFLAGS");
		return 6;
	}

	if(bind(ss, (struct sockaddr *)&local, sizeof(local)) == -1)
	{
		perror("bind");
		return 7;
	}

	return 0;
}

static int init_socket() {
	ss = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(ss < 0) {
		perror("socket");
		return 3;
	}
	return 0;
}

static void free_socket() {
	if(ss != -1) {
		close(ss);
		ss = -1;
	}
}

static void ctrl_c_rx(int sig) {
	fprintf(stderr, "SIGINT...\n");
	free_socket();
}

static int rx_main_loop() {
	signal(SIGINT, ctrl_c_rx);

	uint8_t buff[sizeof(rt_80211_headers) + 8 + MAX_PACKET];
	int len = 0;

	while(0 < (len = read(ss, buff, sizeof(buff)))) {

		uint8_t* pp = buff;
		uint16_t hlen = 0;

		//radiotap header:
		//check version and padding check, get and check header length
		if(len < 36 || pp[0] || pp[1] || len - 24 < (hlen = pp[2] | pp[3] << 8)) {
			continue;
		}

		pp += hlen; //jump to 802.11 frame

		//tupe: data, subtype: 1, duration: 0
		if(pp[0] != 0x08 || pp[1] != 0x01 || pp[2] || pp[3]) {
			continue;
		}

		//jump to MAC addresses
		pp += 4;

		fprintf(stderr, "===rcv: %d bytes, hlen=%d\n", len, hlen);

		// receiver/bssid
		fprintf(stderr, "===rcvr:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n",
				pp[0],
				pp[1],
				pp[2],
				pp[3],
				pp[4],
				pp[5]);

		pp += 6;
		//transmitter/source
		fprintf(stderr, "===trmt:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n",
				pp[0],
				pp[1],
				pp[2],
				pp[3],
				pp[4],
				pp[5]);

		pp += 6;
		//destination
		fprintf(stderr, "===dest:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n",
				pp[0],
				pp[1],
				pp[2],
				pp[3],
				pp[4],
				pp[5]);

		//jump to payload
		pp += 8;

		static uint32_t cnt = 0;
		len -= (pp - buff);

		//output data to stdout
		if(len != write(1, pp, len)) break;

		fprintf(stderr, "===cnt: 0x%x, data len: 0x%X\n", cnt ++, len);
	}
	
	return 0;
}

static int rx_main() {
	int res = 0;
	
	(void)( (res = init_socket()) || (res = set_monitor("mon0")) || (res = rx_main_loop()) );

	free_socket(ss);
	fprintf(stderr, "Exitting...\n");
	return res;
}

static void ctrl_c_tx(int sig) {
	fprintf(stderr, "SIGINT...\n");
	close(0);
}

static int tx_main_loop() {
	signal(SIGINT, ctrl_c_tx);


    uint8_t buff[sizeof(rt_80211_headers) + MAX_PACKET];
    memcpy(buff, rt_80211_headers, sizeof(rt_80211_headers));

	int len = 0;

	while(0 < (len = read(0, buff + sizeof(rt_80211_headers), MAX_PACKET))) {

		len += sizeof(rt_80211_headers);
		if(len != write(ss, buff, len))
			break;
	}

	return 0;
}

static int tx_main() {
	int res = 0;
	
	(void)( (res = init_socket()) || (res = set_monitor("mon0")) || (res = tx_main_loop()) );

	free_socket(ss);
	fprintf(stderr, "Exitting...\n");
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
		return show_usage(argv[0], 1);
	}

	if(!strcmp(argv[1], "rx"))
		return rx_main();
		
	if(!strcmp(argv[1], "tx"))
		return tx_main();

	fprintf(stderr, "\nUnknown subcommand: %s\n", argv[1]);
	return show_usage(argv[0], 2);
}

