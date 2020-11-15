
CC=clang
CFLAGS=-target bpf -Wall -O2

all: icmp-filter.o

clean:
	rm -f *.o

.PHONY: macros
macros:
	clang -target bpf -dM -E - < /dev/null
