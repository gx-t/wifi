all:
	gcc -Wall -O2 -s test00.c -o test00
	mipsel-openwrt-linux-gcc -Wall -O2 -s test00.c -o test00-mips

deb:
	gcc -Wall -g test00.c -o test00
	mipsel-openwrt-linux-gcc -Wall -g test00.c -o test00-mips

ctags:
	ctags -R .

clean:
	rm -f test00 test00-mips tags

