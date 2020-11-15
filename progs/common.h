#pragma once

typedef unsigned char uint8_t;
typedef unsigned long uint64_t;
typedef long int64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

struct frame {
    uint64_t length;
    uint8_t data[0];
};

#define ALEN 6
struct ethhdr {
    uint8_t dst[ALEN];
    uint8_t src[ALEN];
    uint16_t proto;
};

#ifdef __LITTLE_ENDIAN__
#define HTONS(n) ((((uint16_t)(n) & 0x00FF) << 8) | (((uint16_t)(n) & 0xFF00) >> 8))
#define HTONL(n) ((((uint32_t)(n) & 0x000000FF) << 24) | (((uint32_t)(n) & 0x0000FF00) << 8) | \
                  (((uint32_t)(n) & 0x00FF0000) >> 8) | (((uint32_t)(n) & 0xFF000000) >> 24))
#else
#define HTONS(n) (n)
#define HTONL(n) (n)
#endif

struct iphdr {
	uint8_t version_and_ihl;
	uint8_t	tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
};

struct tcphdr {
	uint16_t sport;
	uint16_t dport;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t flags;
	uint16_t window;
	uint16_t csum;
	uint16_t urg_ptr;
};

enum {
	ETHPROTO_IP = 0x0800,
};

enum {
	IPPROTO_TCP = 6,
	IPPROTO_UDP = 17,
	IPPROTO_ICMP =1
};

static long (*bpf_trace_printk)(const char *fmt, int fmt_size) = (void *)6;

#define printk(fmt) \
  ({ const char __fmt[] = fmt; \
     bpf_trace_printk(__fmt, sizeof(__fmt)); \
  })

static long (*bpf_ktime_get_ns)(void) = (void *)5;

static inline void print_ethernet_address(struct frame *frame) {
    struct ethhdr *hdr = (struct ethhdr*)frame->data;
    char src[5+ALEN*2+1] = {0,};
    for (int i = 0, j = 0; i < ALEN; i++) {
        src[j] = ((hdr->src[i]&0xF0)>>4)&0xF;
        src[j] += (src[j] <= 9) ? '0' : ('A' - 10);
        j++;
        src[j] = hdr->src[i]&0x0F;
        src[j] += (src[j] <= 9) ? '0' : ('A' - 10);
        j++;
        if (i+1 < ALEN) {
    	    src[j] = ':';
    	    j++;
        }
    }
    bpf_trace_printk(src, sizeof(src));
}

