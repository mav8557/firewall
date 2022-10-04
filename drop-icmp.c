#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <linux/types.h>
//#include <uapi/linux/bpf.h>
//#include <net/sock.h>
//#include <net/udp_tunnel.h>
//#include <net/inet_sock.h>
//

typedef unsigned short u16;
typedef unsigned int u32;
//typedef unsigned int pid_size_t
//typedef unsigned int uid_size_t


#define TASK_COMM_LEN 16


#define DEBUG 1
#define MAPSIZE 12000

#ifdef DEBUG
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})
#endif

// pleeeeease let me call bpf_trace_printk
char LICENSE[] SEC("license") = "GPL\0but who really cares?";

struct tcp_key_t {
	u16 sport;
	u32 daddr;
	u16 dport;
	u32 saddr;
}__attribute__((packed));

struct tcp_value_t {
	u16 pid;
	u16 uid;
	char comm[TASK_COMM_LEN];
}__attribute__((packed));


struct bpf_map_def SEC("maps/tcpMap") tcpMap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcp_key_t),
	.value_size = sizeof(struct tcp_value_t),
	.max_entries = MAPSIZE+1,
};

__attribute__((section("egress"), used))
int drop(struct __sk_buff *skb) {
    const int l3_off = ETH_HLEN;                      // IP header offset
    const int l4_off = l3_off + sizeof(struct iphdr); // L4 header offset
    //u32 pid = bpf_get_current_pid_tgid();


    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    if (data_end < data + l4_off)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
       return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(data + l3_off);

    // block ICMP egress to cloudflare DNS 1.1.1.1
    if (ip->protocol == IPPROTO_ICMP && ip->daddr == 16843009) {
        bpf_printk("cloudflare bing chilling\n");
        return TC_ACT_SHOT;
    }

    // drop ICMP traffic to cloudflare, allow the rest
    return TC_ACT_OK;
    //return ip->protocol == IPPROTO_ICMP ? TC_ACT_SHOT : TC_ACT_OK;
}
