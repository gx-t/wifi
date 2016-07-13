all:
	gcc -Wall -O2 -s test00.c -o test00
	mipsel-openwrt-linux-gcc -Wall -O2 -s test00.c -o test00-mips

deb:
	gcc -Wall -g test00.c -o test00
	mipsel-openwrt-linux-gcc -Wall -g test00.c -o test00-mips

filter:
	(sudo tcpdump -dd -i mon0 \
	ether src 13:22:33:44:55:66 and \
	ether dst 13:22:33:44:55:66 and \
	'ether[0]=8 && ether[1]=1 && ether[2]=0 && ether[3]=0') > test00-filter.h

ctags:
	ctags -R .

clean:
	rm -f test00 test00-mips test00-filter.h tags

