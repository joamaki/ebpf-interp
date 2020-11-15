all: build

.PHONY: build
build: progs cmd/ebpf-capture/ebpf-capture

.PHONY:	cmd/ebpf-capture/ebpf-capture
cmd/ebpf-capture/ebpf-capture:
	cd cmd/ebpf-capture && go build
	
.PHONY: progs
progs:
	cd progs && make

fmt:
	go fmt
	(cd cmd/ebpf-capture && go fmt)

run: build
	sudo cmd/ebpf-capture/ebpf-capture progs/icmp-filter.o lo
