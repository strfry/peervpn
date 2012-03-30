CC=cc
CFLAGS=-Os
LDFLAGS=-lcrypto -ldl -lz

all: peervpn
peervpn: peervpn.o

clean:
	rm -f peervpn peervpn.o
