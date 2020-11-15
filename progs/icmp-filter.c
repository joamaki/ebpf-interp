
#include "common.h"

__attribute__((section("socket/test"), used))
uint64_t test(struct frame *frame) {
    struct ethhdr *ehdr = (struct ethhdr*)frame->data;

    if (ehdr->proto == HTONS(ETHPROTO_IP)) {
        struct iphdr *iphdr = (struct iphdr*)(frame->data + sizeof(struct ethhdr));
        if (iphdr->protocol == IPPROTO_ICMP) {
	        return 1;
        } else {
	        return 0;
        }

    } else {
	    return 0;
    }
}

