#!/usr/bin/env bash

# Socket Filter Program Generator

# CONSTANTS HERE DEPEND ON RADIOTAP HEADER AND 802.11 FRAME HEADER IN C SOURCE
tcpdump -dd -i mon0 \
			ether src 13:22:33:44:55:66 and \
			ether dst 13:22:33:44:55:66 and \
			'len >= 38
			&& radio[0] = 0x00 && radio[1] = 00
			&& ((radio[2] | radio[3] << 8) < (len - 0x18))
			&& ether[0] = 0x08 && ether[1] = 0x01
			&& ether[2] = 0x00 && ether[3] = 0x00'

