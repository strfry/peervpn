CC=gcc 
CFLAGS=-Wall -O3
LDFLAGS=-lssl

all: peervpn
peervpn: peervpn.o

clean:
	rm -f peervpn peervpn.o
