#!/bin/sh
set -exuo pipefail

(cd cmd/ebpf-capture && go build)
(cd progs && make)

sudo cmd/ebpf-capture/ebpf-capture progs/icmp-filter.o lo
