all:
	gcc -Wall -O2 -s test00.c -o test00
	mipsel-openwrt-linux-gcc -Wall -O2 -s test00.c -o test00-mips

deb:
	gcc -Wall -g test00.c -o test00
	mipsel-openwrt-linux-gcc -Wall -g test00.c -o test00-mips

filter:
	(sudo ./gen-filter.sh) > test00-filter.h

monitor:
	sudo iw phy phy0 interface add mon0 type monitor
	sudo ifconfig mon0 up

ctags:
	ctags -R .

clean:
	rm -f test00 test00-mips test00-filter.h tags

