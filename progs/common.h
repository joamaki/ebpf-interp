#pragma once

typedef unsigned long uint64_t;
typedef long int64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

struct frame {
    uint64_t length;
    unsigned char data[0];
};

#define ALEN 6
struct ethhdr {
    unsigned char dst[ALEN];
    unsigned char src[ALEN];
    unsigned short proto;
};

#ifdef __LITTLE_ENDIAN__
#define HTONS(n) ((((uint16_t)(n) & 0x00FF) << 8) | (((uint16_t)(n) & 0xFF00) >> 8))
#define HTONL(n) ((((uint32_t)(n) & 0x000000FF) << 24) | (((uint32_t)(n) & 0x0000FF00) << 8) | \
                  (((uint32_t)(n) & 0x00FF0000) >> 8) | (((uint32_t)(n) & 0xFF000000) >> 24))
#else
#define HTONS(n) (n)
#define HTONL(n) (n)
#endif

typedef unsigned char __u8;
typedef unsigned short __be16;
typedef unsigned short __sum16;
typedef unsigned int __be32;
struct iphdr {
	__u8	ihl:4,
		version:4;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
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

