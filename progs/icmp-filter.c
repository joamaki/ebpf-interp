#include "common.h"

__attribute__((section("socket/test"), used))
uint64_t test(struct frame *frame) {
	struct ethhdr *ehdr = (struct ethhdr*)frame->data;
	if (ehdr->proto == HTONS(ETHPROTO_IP)) {
		struct iphdr *iphdr = (struct iphdr*)(frame->data + sizeof(struct ethhdr));
		return iphdr->protocol == IPPROTO_ICMP;
	}
	return 0;
}

