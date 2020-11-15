
CC=clang
CFLAGS=-target bpf -Wall -O2

all: icmp-filter.o tcp-port-filter.o

icmp-filter.o: common.h
tcp-port-filter.o: common.h

clean:
	rm -f *.o

.PHONY: macros
macros:
	clang -target bpf -dM -E - < /dev/null
