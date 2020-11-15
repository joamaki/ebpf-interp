#include "common.h"

__attribute__((section("socket/test"), used))
uint64_t test(struct frame *frame) {
	struct ethhdr *ehdr = (struct ethhdr*)frame->data;
	if (ehdr->proto == HTONS(ETHPROTO_IP)) {
		struct iphdr *iphdr = (struct iphdr*)(frame->data + sizeof(struct ethhdr));
		uint8_t iphdr_size = (iphdr->version_and_ihl & 0x0f) * 4;
		if (iphdr->protocol == IPPROTO_TCP) {
                	struct tcphdr *tcphdr = (struct tcphdr*)(frame->data + sizeof(struct ethhdr) + iphdr_size);
                	return tcphdr->dport == HTONS(22);
		}
	}
	return 0;
}

