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


#ifndef F_NDP6_C
#define F_NDP6_C


#include "../libp2psec/map.c"
#include "../libp2psec/util.c"
#include "checksum.c"


// Constants.
#define ndp6_TABLE_SIZE 16384
#define ndp6_ADDR_SIZE 16
#define ndp6_MAC_SIZE 6


// Constraints.
#if ndp6_ADDR_SIZE != 16
#error ndp6_ADDR_SIZE != 16
#endif
#if ndp6_MAC_SIZE != 6
#error ndp6_MAC_SIZE != 6
#endif


// The NDP6 structure.
struct s_ndp6_state {
	struct s_map ndptable;
};


// Scan Ethernet frame for NDP messages.
static void ndp6ScanFrame(struct s_ndp6_state *ndpstate, const unsigned char *frame, const int frame_len) {
	const unsigned char *ipv6addr;
	const unsigned char *macaddr;
	if(frame_len >= 86) {
		if(((frame[14] >> 4) == 6) && (frame[20] == 0x3a)) {
			if(frame[54] == 0x88) {
				// neighbor advertisement
				ipv6addr = &frame[62];
				macaddr = &frame[80];
				mapSet(&ndpstate->ndptable, ipv6addr, macaddr);
			}
			if(frame[54] == 0x87) {
				// neighbor solicitation
				ipv6addr = &frame[22];
				macaddr = &frame[80];
				mapSet(&ndpstate->ndptable, ipv6addr, macaddr);
			}
		}
	}
}


// Generate neighbor advertisement. Returns length of generated answer.
static int ndp6GenAdvFrame(unsigned char *outbuf, const int outbuf_len, const unsigned char *src_addr, const unsigned char *dest_addr, const unsigned char *src_mac, const unsigned char *dest_mac) {
	struct s_checksum checksum;
	unsigned char ph[16];
	int i;
	uint16_t u;
	if(outbuf_len >= 86) {
		// generate message
		memcpy(&outbuf[0], dest_mac, ndp6_MAC_SIZE); // destination MAC
		memcpy(&outbuf[6], src_mac, ndp6_MAC_SIZE); // source MAC
		memcpy(&outbuf[12], "\x86\xdd\x60\x00\x00\x00\x00\x20\x3a\xff", 10); // IPv6 header (payloadlength 32, nextheader ICMPv6)
		memcpy(&outbuf[22], src_addr, ndp6_ADDR_SIZE); // source IPv6 address
		memcpy(&outbuf[38], dest_addr, ndp6_ADDR_SIZE); // destination IPv6 address
		memcpy(&outbuf[54], "\x88\x00\x00\x00", 4); // ICMPv6 header
		memcpy(&outbuf[58], "\x00\x00\x00\x00", 4); // flags
		memcpy(&outbuf[62], src_addr, ndp6_ADDR_SIZE); // target IPv6 address
		memcpy(&outbuf[78], "\x02\x01", 2); // ICMPv6 option header
		memcpy(&outbuf[80], src_mac, ndp6_MAC_SIZE); // target MAC address
		
		// calculate checksum
		checksumZero(&checksum); // reset checksum
		for(i=0; i<32; i=i+2) checksumAdd(&checksum, *((uint16_t *)(&outbuf[22+i]))); // IPv6 pseudoheader src+dest address
		memset(ph, 0, 16);
		utilWriteInt32(&ph[0], 32); // payload length
		utilWriteInt32(&ph[4], 58); // nextheader
		for(i=0; i<8; i=i+2) checksumAdd(&checksum, *((uint16_t *)(&ph[i]))); // IPv6 pseudoheader payload length & nextheader
		for(i=0; i<32; i=i+2) checksumAdd(&checksum, *((uint16_t *)(&outbuf[54+i]))); // ICMPv6 message

		// write checksum
		u = checksumGet(&checksum);
		memcpy(&outbuf[56], &u, 2);
		return 86;
	}
	return 0;
}


// Scan Ethernet frame for neighbour solicitation and generate answer neighbor advertisement. Returns length of generated answer.
static int ndp6GenAdv(struct s_ndp6_state *ndpstate, const unsigned char *frame, const int frame_len, unsigned char *advbuf, const int advbuf_len) {
	const unsigned char *ipv6addr;
	const unsigned char *macaddr;
	const unsigned char *reqipv6addr;
	const unsigned char *resmacaddr;
	if(frame_len >= 86) {
		if(((frame[14] >> 4) == 6) && (frame[20] == 0x3a) && (frame[54] == 0x87)) {
			ipv6addr = &frame[22];
			macaddr = &frame[80];
			
			// resolve requested ipv6 address
			reqipv6addr = &frame[62];
			resmacaddr = mapGet(&ndpstate->ndptable, reqipv6addr);
			if(resmacaddr != NULL) {
				// generate answer
				return ndp6GenAdvFrame(advbuf, advbuf_len, reqipv6addr, ipv6addr, resmacaddr, macaddr);
			}
		}
	}
	return 0;
}


// Generate NDP table status report.
static void ndp6Status(struct s_ndp6_state *ndpstate, char *report, const int report_len) {
	int pos = 0;
	int size = mapGetMapSize(&ndpstate->ndptable);
	int maxpos = (((size + 2) * (60)) + 1);
	unsigned char infoipv6addr[ndp6_ADDR_SIZE];
	unsigned char infomacaddr[ndp6_MAC_SIZE];
	int i;
	int j;
	
	if(maxpos > report_len) { maxpos = report_len; }
	
	memcpy(&report[pos], "IPv6 address                             MAC address      ", 58);
	pos = pos + 58;
	report[pos++] = '\n';

	i = 0;
	while(i < size && pos < maxpos) {
		if(mapIsValidID(&ndpstate->ndptable, i)) {
			memcpy(infoipv6addr, mapGetKeyByID(&ndpstate->ndptable, i), ndp6_ADDR_SIZE);
			memcpy(infomacaddr, mapGetValueByID(&ndpstate->ndptable, i), ndp6_MAC_SIZE);
			j = 0;
			while(j < (ndp6_ADDR_SIZE / 2)) {
				utilByteArrayToHexstring(&report[pos + (j * 5)], (4 + 2), &infoipv6addr[(j*2)], 2);
				report[pos + (j * 5) + 4] = ':';
				j++;
			}
			pos = pos + ((ndp6_ADDR_SIZE * 2) + (ndp6_ADDR_SIZE / 2) - 1);
			report[pos++] = ' ';
			report[pos++] = ' ';
			j = 0;
			while(j < ndp6_MAC_SIZE) {
				utilByteArrayToHexstring(&report[pos + (j * 3)], (2 + 2), &infomacaddr[j], 1);
				report[pos + (j * 3) + 2] = ':';
				j++;
			}
			pos = pos + ((ndp6_MAC_SIZE * 2) + (ndp6_MAC_SIZE) - 1);
			report[pos++] = '\n';
		}
		i++;
	}
	report[pos++] = '\0';
}


// Create NDP6 structure.
static int ndp6Create(struct s_ndp6_state *ndpstate) {
	if(mapCreate(&ndpstate->ndptable, ndp6_TABLE_SIZE, ndp6_ADDR_SIZE, ndp6_MAC_SIZE)) {
		mapEnableReplaceOld(&ndpstate->ndptable);
		mapInit(&ndpstate->ndptable);
		return 1;
	}
	return 0;
}


// Destroy NDP6 structure.
static void ndp6Destroy(struct s_ndp6_state *ndpstate) {
	mapDestroy(&ndpstate->ndptable);
}


#endif // F_NDP6_C
