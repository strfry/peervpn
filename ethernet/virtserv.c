/***************************************************************************
 *   Copyright (C) 2012 by Tobias Volk                                     *
 *   mail@tobiasvolk.de                                                    *
 *                                                                         *
 *   This program is free software: you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation, either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/


#ifndef F_VIRTSERV_C
#define F_VIRTSERV_C


#include "../libp2psec/map.c"
#include "ndp6.c"


// Constants.
#define virtserv_LISTENADDR_COUNT 8
#define virtserv_ADDR_SIZE 16
#define virtserv_MAC_SIZE 6
#define virtserv_MAC "\x00\x22\x00\xed\x13\x37"


// Constraints.
#if virtserv_ADDR_SIZE != 16
#error virtserv_ADDR_SIZE != 16
#endif
#if virtserv_MAC_SIZE != 6
#error virtserv_MAC_SIZE != 6
#endif


// The virtual service structure.
struct s_virtserv_state {
	struct s_map listenaddrs;
	unsigned char mac[virtserv_MAC_SIZE];
};


// Add address to virtual service
static int virtservAddAddress(struct s_virtserv_state *virtserv, const unsigned char *ipv6address) {
	int tnow;
	tnow = utilGetTime();
	return mapAdd(&virtserv->listenaddrs, ipv6address, &tnow);
}


// Returns 1 if mac address is the mac address of the virtual service.
static int virtservCheckMac(struct s_virtserv_state *virtserv, const unsigned char *macaddress) {
	return (memcmp(virtserv->mac, macaddress, virtserv_MAC_SIZE) == 0);
}


// Returns 1 if address is a listen address of the virtual service.
static int virtservCheckAddress(struct s_virtserv_state *virtserv, const unsigned char *ipv6address) {
	return (mapGet(&virtserv->listenaddrs, ipv6address) != NULL);
}


// Decode ICMPv6 message.
static int virtservDecodeICMPv6(struct s_virtserv_state *virtserv, unsigned char *outbuf, const int outbuf_len, const unsigned char *inbuf, const int inbuf_len) {
	if((inbuf_len >= 8) && (outbuf_len >= inbuf_len)) {
		if((inbuf[0] == 0x80) && (inbuf[1] == 0x00)) { // Echo Request
			outbuf[0] = 0x81; // Echo Reply
			outbuf[1] = 0x00; // code 0
			outbuf[2] = (inbuf[2] - 1); // checksum MSB
			if(inbuf[2] == 0x00) {
				outbuf[3] = (inbuf[3] - 1); // checksum LSB
			}
			else {
				outbuf[3] = inbuf[3]; // checksum LSB
			}
			memcpy(&outbuf[4], &inbuf[4], (inbuf_len - 4));
			return inbuf_len;
		}
	}
	return 0;
}


// Decode frame for virtual service. Returns length of the response.
static int virtservDecodeFrame(struct s_virtserv_state *virtserv, unsigned char *outframe, const int outframe_len, const unsigned char *inframe, const int inframe_len) {
	if(inframe[20] == 0x3a){ // packet is ICMPv6
		outframe[20] = 0x3a; // nextheader: ICMPv6
		return (virtservDecodeICMPv6(virtserv, &outframe[54], (outframe_len - 54), &inframe[54], (inframe_len - 54)) + 54);
	}
	return 0;
}


// Send frame to the virtual service. Returns length of the response.
static int virtservFrame(struct s_virtserv_state *virtserv, unsigned char *outframe, const int outframe_len, const unsigned char *inframe, const int inframe_len) {
	const unsigned char *src_ipv6addr;
	const unsigned char *src_macaddr;
	const unsigned char *dest_ipv6addr;
	const unsigned char *dest_macaddr;
	const unsigned char *req_ipv6addr;
	int outlen;
	if((inframe_len >= 86) && (outframe_len >= 86)) {
		src_ipv6addr = &inframe[22];
		src_macaddr = &inframe[6];
		if(
		((src_macaddr[0] & 0x01) == 0) &&	// unicast source MAC
		((inframe[14] >> 4) == 6) &&		// packet is IPv6
		(src_ipv6addr[0] != 0xff)		// unicast source address
		) {
			dest_ipv6addr = &inframe[38];
			dest_macaddr = &inframe[0];
			if((dest_macaddr[0] & 0x01) == 0) {
				if((dest_ipv6addr[0] != 0xff) && (virtservCheckMac(virtserv, dest_macaddr)) && (virtservCheckAddress(virtserv, dest_ipv6addr))) {
					outlen = virtservDecodeFrame(virtserv, outframe, outframe_len, inframe, inframe_len);
					if(outlen > 54) {
						memcpy(&outframe[0], src_macaddr, ndp6_MAC_SIZE); // destination MAC
						memcpy(&outframe[6], dest_macaddr, ndp6_MAC_SIZE); // source MAC
						memcpy(&outframe[12], "\x86\xdd\x60\x00\x00\x00\x00\x00", 8); // header
						utilWriteInt16(&outframe[18], (outlen - 54)); // payload length
						// &outframe[20]: nextheader (1 byte)
						outframe[21] = inframe[21]; // TTL
						memcpy(&outframe[22], dest_ipv6addr, ndp6_ADDR_SIZE); // source IPv6 address
						memcpy(&outframe[38], src_ipv6addr, ndp6_ADDR_SIZE); // destination IPv6 address
						return outlen;
					}
					else {
						return ndp6GenAdvFrame(outframe, outframe_len, dest_ipv6addr, src_ipv6addr, virtserv->mac, src_macaddr, 0);
					}
				}
			}
			else {
				if(
				(inframe[20] == 0x3a) &&		// packet is ICMPv6
				(inframe[21] == 0xff) &&		// TTL is 255
				(inframe[54] == 0x87) &&		// packet is neighbor solicitation
				(memcmp(src_macaddr, &inframe[80], virtserv_MAC_SIZE) == 0)	// source mac addresses match
				) {
					req_ipv6addr = &inframe[62];
					if(virtservCheckAddress(virtserv, req_ipv6addr)) {
						return ndp6GenAdvFrame(outframe, outframe_len, req_ipv6addr, src_ipv6addr, virtserv->mac, src_macaddr, 1);
					}
				}
			}
		}
	}
	return 0;
}


// Create virtual service.
static int virtservCreate(struct s_virtserv_state *virtserv) {
	unsigned char mymacaddr[virtserv_MAC_SIZE];
	unsigned char myipv6addr[virtserv_ADDR_SIZE];

	// generate link local address
	memcpy(mymacaddr, virtserv_MAC, virtserv_MAC_SIZE);
	memcpy(&myipv6addr[0], "\xFE\x80\x00\x00\x00\x00\x00\x00", 8);
	myipv6addr[8] = (mymacaddr[0] | 0x02);
	memcpy(&myipv6addr[9], &mymacaddr[1], 2);
	memcpy(&myipv6addr[11], "\xFF\xFE", 2);
	memcpy(&myipv6addr[13], &mymacaddr[3], 3);

	// add listen address
	if(mapCreate(&virtserv->listenaddrs, virtserv_LISTENADDR_COUNT, virtserv_ADDR_SIZE, 1)) {
		mapInit(&virtserv->listenaddrs);
		if(virtservAddAddress(virtserv, myipv6addr)) {
			memcpy(virtserv->mac, mymacaddr, virtserv_MAC_SIZE);
			return 1;
		}
		mapDestroy(&virtserv->listenaddrs);
	}
	return 0;
}


// Destroy virtual service.
static void virtservDestroy(struct s_virtserv_state *virtserv) {
	mapDestroy(&virtserv->listenaddrs);
}


#endif // F_VIRTSERV_C
