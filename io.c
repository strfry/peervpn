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


#ifndef F_IO_C
#define F_IO_C


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/if_tun.h>


// IDs.
#define IO_FDID_CONSOLE 0
#define IO_FDID_UDPV4SOCKET 1
#define IO_FDID_UDPV6SOCKET 2
#define IO_FDID_TAP 3
#define IO_FDID_COUNT 4


// The IO state structure.
struct s_io_state {
	struct pollfd fd[IO_FDID_COUNT];
};


// The IPv4 addr/port structure.
struct s_io_v4addr {
	unsigned char addr[4];
	unsigned char port[2];
};


// The IPv6 addr/port structure.
struct s_io_v6addr {
	unsigned char addr[16];
	unsigned char port[2];
};


// Opens TAP device. Returns 1 if successful.
static int ioOpenTap(struct s_io_state *iostate, const char *tapname) {
	struct ifreq ifr;
	char *file = "/dev/net/tun";
	int tapfd = open(file,(O_RDWR | O_NONBLOCK));

	if(tapfd < 0) {
		return 0;
	}

	memset(&ifr,0,sizeof(ifr));
	ifr.ifr_flags = (IFF_TAP | IFF_NO_PI);
	strncpy(ifr.ifr_name, tapname, sizeof(ifr.ifr_name) - 1);
	if(ioctl(tapfd,TUNSETIFF,(void *)&ifr) < 0) {
		return 0;
	}

	iostate->fd[IO_FDID_TAP].fd = tapfd;
	iostate->fd[IO_FDID_TAP].events = POLLIN;
	return 1;
}


// Writes to TAP device. Returns number of bytes written.
static int ioWriteTap(struct s_io_state *iostate, const unsigned char *buf, const int len) {
	return write(iostate->fd[IO_FDID_TAP].fd, buf, len);
}


// Reads from TAP device. Returns number of bytes read.
static int ioReadTap(struct s_io_state *iostate, unsigned char *buf, const int len) {
	return read(iostate->fd[IO_FDID_TAP].fd, buf, len);
}


// Opens a socket. Returns 1 if successful.
static int ioOpenSocket(int *handle, const char *bindaddress, const char *bindport, const int domain, const int type, const int protocol) {
	int ret;
	int fd;
	int one = 1;
	const char *zeroport = "0";
	const char *useport;
	const char *useaddr;
	struct addrinfo *d = NULL;
	struct addrinfo *di;
	struct addrinfo hints;
	if((fd = socket(domain, type, 0)) < 0) return 0;
	if((fcntl(fd,F_SETFL,O_NONBLOCK)) < 0) return 0;
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(int));
	memset(&hints,0,sizeof(struct addrinfo));
	hints.ai_family = domain;
	hints.ai_socktype = type;
	hints.ai_flags = AI_PASSIVE;
	if(bindaddress == NULL) {
		useaddr = NULL;
	}
	else {
		if(strlen(bindaddress) > 0) {
			useaddr = bindaddress;
		}
		else {
			useaddr = NULL;
		}
	}
	if(bindport == NULL) {
		useport = zeroport;
	}
	else {
		useport = bindport;
	}
	if(getaddrinfo(useaddr, useport, &hints, &d) == 0) {
		ret = -1;
		di = d;
		while(di != NULL) {
			if(bind(fd, di->ai_addr, di->ai_addrlen) == 0) {
				ret = fd;
				break;
			}
			di = di->ai_next;
		}
		freeaddrinfo(d);
		if(ret < 0) {
			close(fd);
			return 0;
		}
		*handle = ret;
		return 1;
	}
	else {
		return 0;
	}
}


// Get IPv6 UDP address from name. Returns 1 if successful.
static int ioGetUDPv6Address(struct s_io_v6addr *addr, const char *hostname, const char *port) {
	int ret;
	struct sockaddr_in6 *saddr;
	struct addrinfo *d = NULL;
	struct addrinfo hints;
	if(hostname != NULL && port != NULL) {
		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;
		if(getaddrinfo(hostname, port, &hints, &d) == 0) {
			if(d != NULL) {
				saddr = (struct sockaddr_in6 *)d->ai_addr;
				memcpy(addr->addr, saddr->sin6_addr.s6_addr, 16);
				memcpy(addr->port, &saddr->sin6_port, 2);
				ret = 1;
			}
			else {
				ret = 0;
			}
			freeaddrinfo(d);
		}
		else {
			ret = 0;
		}
		return ret;
	}
	else {
		return 0;
	}
}


// Opens an IPv6 UDP socket. Returns 1 if successful.
static int ioOpenUDPv6Socket(struct s_io_state *iostate, const char *bindaddress, const char *bindport) {
	int fd;
	if(ioOpenSocket(&fd, bindaddress, bindport, AF_INET6, SOCK_DGRAM, 0)) {
		iostate->fd[IO_FDID_UDPV6SOCKET].fd = fd;
		iostate->fd[IO_FDID_UDPV6SOCKET].events = POLLIN;
		return 1;
	}
	else {
		return 0;
	}
}


// Sends an IPv6 UDP packet. Returns length of sent message.
static int ioSendUDPv6Packet(struct s_io_state *iostate, const unsigned char *buf, const int len, struct s_io_v6addr *destination) {
	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
	memcpy(addr.sin6_addr.s6_addr, destination->addr, 16);
	memcpy(&addr.sin6_port, destination->port, 2);
	return sendto(iostate->fd[IO_FDID_UDPV6SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6));
}


// Receives an IPv6 UDP packet. Returns length of received message.
static int ioRecvUDPv6Packet(struct s_io_state *iostate, unsigned char *buf, const int len, struct s_io_v6addr *source) {
	struct sockaddr_in6 addr;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	int ret = recvfrom(iostate->fd[IO_FDID_UDPV6SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, &addrlen);
	if(ret > 0) {
		memcpy(source->addr, addr.sin6_addr.s6_addr, 16);
		memcpy(source->port, &addr.sin6_port, 2);
	}
	return ret;
}


// Convert UDPv6 address to 24 bit address.
static void ioConvertAddressFromUDPv6(unsigned char *address, const struct s_io_v6addr *v6addr) {
	memset(address, 0, 24);
	address[0] = 1;
	address[1] = 6;
	address[2] = 1;
	memcpy(&address[4], &v6addr->addr, 16);
	memcpy(&address[20], v6addr->port, 2);
}


// Get IPv4 UDP address from name. Returns 1 if successful.
static int ioGetUDPv4Address(struct s_io_v4addr *addr, const char *hostname, const char *port) {
	int ret;
	struct sockaddr_in *saddr;
	struct addrinfo *d = NULL;
	struct addrinfo hints;
	if(hostname != NULL && port != NULL) {
		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;
		if(getaddrinfo(hostname, port, &hints, &d) == 0) {
			if(d != NULL) {
				saddr = (struct sockaddr_in *)d->ai_addr;
				memcpy(addr->addr, &saddr->sin_addr.s_addr, 4);
				memcpy(addr->port, &saddr->sin_port, 2);
				ret = 1;
			}
			else {
				ret = 0;
			}
			freeaddrinfo(d);
		}
		else {
			ret = 0;
		}
		return ret;
	}
	else {
		return 0;
	}
}


// Opens an IPv4 UDP socket. Returns 1 if successful.
static int ioOpenUDPv4Socket(struct s_io_state *iostate, const char *bindaddress, const char *bindport) {
	int fd;
	if(ioOpenSocket(&fd, bindaddress, bindport, AF_INET, SOCK_DGRAM, 0)) {
		iostate->fd[IO_FDID_UDPV4SOCKET].fd = fd;
		iostate->fd[IO_FDID_UDPV4SOCKET].events = POLLIN;
		return 1;
	}
	else {
		return 0;
	}
}


// Sends an IPv4 UDP packet. Returns length of sent message.
static int ioSendUDPv4Packet(struct s_io_state *iostate, const unsigned char *buf, const int len, const struct s_io_v4addr *destination) {
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	memcpy(&addr.sin_addr.s_addr, destination->addr, 4);
	memcpy(&addr.sin_port, destination->port, 2);
	return sendto(iostate->fd[IO_FDID_UDPV4SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}


// Receives an IPv4 UDP packet. Returns length of received message.
static int ioRecvUDPv4Packet(struct s_io_state *iostate, unsigned char *buf, const int len, struct s_io_v4addr *source) {
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int ret = recvfrom(iostate->fd[IO_FDID_UDPV4SOCKET].fd, buf, len, 0, (struct sockaddr *)&addr, &addrlen);
	if(ret > 0) {
		memcpy(source->addr, &addr.sin_addr.s_addr, 4);
		memcpy(source->port, &addr.sin_port, 2);
	}
	return ret;
}


// Convert UDPv4 address to 24 bit address.
static void ioConvertAddressFromUDPv4(unsigned char *address, const struct s_io_v4addr *v4addr) {
	memset(address, 0, 24);
	address[0] = 1;
	address[1] = 4;
	address[2] = 1;
	memcpy(&address[4], v4addr->addr, 4);
	memcpy(&address[8], v4addr->port, 2);
}


// Get 24 bit address (UDP over IPv4 or IPv6) from hostname/port. Returns 1 if successful.
static int ioGetUDPAddress(struct s_io_state *iostate, unsigned char *address, const char *hostname, const char *port) {
	struct s_io_v4addr v4addr;
	struct s_io_v6addr v6addr;
	
	if((!(iostate->fd[IO_FDID_UDPV6SOCKET].fd < 0)) && (ioGetUDPv6Address(&v6addr, hostname, port))) {
		ioConvertAddressFromUDPv6(address, &v6addr);
		return 1;
	}
	if((!(iostate->fd[IO_FDID_UDPV4SOCKET].fd < 0)) && (ioGetUDPv4Address(&v4addr, hostname, port))) {
		ioConvertAddressFromUDPv4(address, &v4addr);
		return 1;
	}
	
	return 0;
}


// Send a packet and detect protocol using the 24 bit destination address. Returns length of sent message.
static int ioSendPacket(struct s_io_state *iostate, const unsigned char *buf, const int len, const unsigned char *destination) {
	struct s_io_v4addr v4addr;
	struct s_io_v6addr v6addr;
	
	// char text[64]; utilByteArrayToHexstring(text, 64, destination, 24); printf("(debug)    sending packet to %s\n", text);

	switch(destination[0]) {
		case 1:
			// default protocol set
			switch(destination[1]) {
				case 6:
					// IPv6
					switch(destination[2]) {
						case 1:
							// UDP over IPv6
							memcpy(v6addr.addr, &destination[4], 16);
							memcpy(v6addr.port, &destination[20], 2);
							return ioSendUDPv6Packet(iostate, buf, len, &v6addr);
						break;
					}
				break;
				case 4:
					// IPv4
					switch(destination[2]) {
						case 1:
							// UDP over IPv4
							memcpy(v4addr.addr, &destination[4], 4);
							memcpy(v4addr.port, &destination[8], 2);
							return ioSendUDPv4Packet(iostate, buf, len, &v4addr);
						break;
					}
				break;
			}
			break;
	}
	
	return -1;
}


// Receive a packet and generate the 24 bit source address depending on the protocol. Returns length of received message.
static int ioRecvPacket(struct s_io_state *iostate, unsigned char *buf, const int len, unsigned char *source) {
	int ret;
	struct s_io_v4addr v4addr;
	struct s_io_v6addr v6addr;

	if((!(iostate->fd[IO_FDID_UDPV6SOCKET].fd < 0)) && ((ret = (ioRecvUDPv6Packet(iostate, buf, len, &v6addr))) > 0)) {
		// received UDP over IPv6
		ioConvertAddressFromUDPv6(source, &v6addr);
		// char text[64]; utilByteArrayToHexstring(text, 64, source, 24); printf("(debug) received packet from %s\n", text);
		return ret;
	}
	if((!(iostate->fd[IO_FDID_UDPV4SOCKET].fd < 0)) && ((ret = (ioRecvUDPv4Packet(iostate, buf, len, &v4addr))) > 0)) {
		// received UDP over IPv4
		ioConvertAddressFromUDPv4(source, &v4addr);
		// char text[64]; utilByteArrayToHexstring(text, 64, source, 24); printf("(debug) received packet from %s\n", text);
		return ret;
	}
	
	return -1;
}


// Wait for data.
static void ioWait(struct s_io_state *iostate, const int max_wait) {
	poll(iostate->fd,IO_FDID_COUNT,max_wait);
}


// Initialize IO state.
static void ioCreate(struct s_io_state *iostate) {
	int i;
	for(i=0; i<IO_FDID_COUNT; i++) {
		iostate->fd[i].fd = -1;
		iostate->fd[i].events = 0;
	}
}


// Close all opened FDs.
static void ioReset(struct s_io_state *iostate) {
	int i;
	for(i=0; i<IO_FDID_COUNT; i++) {
		if(!(iostate->fd[i].fd < 0)) {
			close(iostate->fd[i].fd);
		}
	}
	ioCreate(iostate);
}


#endif // F_IO_C 
