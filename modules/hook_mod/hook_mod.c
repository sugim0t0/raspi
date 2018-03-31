/**
 * Send/Recv packets hook module by netfilter
 * Test Linux kernel version: 4.9.80
 *
 * @author Sugimoto
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/arp.h>
#include <net/route.h>

#define RECV_MODE 0
#define SEND_MODE 1
//#define HOOK_MODE RECV_MODE
#define HOOK_MODE SEND_MODE

#if (HOOK_MODE == RECV_MODE)
/* 172.29.46.79 */
#define DST_IP_ADDRESS 0xAC1D2E4F
#else
/* 172.29.47.152 */
#define DST_IP_ADDRESS 0xAC1D2F98
#endif
#define PORT_NUMBER 12345

#define RASPI_CKSUM_OFFLOAD 1
#define HOOK_PACKET_DROP    0
#define DEBUG_PRINT         1

MODULE_DESCRIPTION("Send/Recv packets hook module by netfilter");
MODULE_AUTHOR("sugimoto");
MODULE_LICENSE("GPL");

/* static variable */
static struct nf_hook_ops netfilter_ops_in;

/* function */
void dump_data(unsigned char* data, int size)
{
    int i;
    for(i = 0; i < size; i++)
    {
        printk("[%d]%02x", i, *(data + i));
    }
}

void print_skb_info(struct sk_buff *skb)
{
    printk("---- SKBUF info ----\n");
    printk("len:       %u\n", skb->len);
    printk("data_len:  %u\n", skb->data_len);
    printk("head addr: %p\n", skb->head);
    printk("data addr: %p\n", skb->data);
    printk("tail addr: %p\n", skb->tail);
    printk("end addr:  %p\n", skb->end);
    printk("csum:      %u\n", skb->csum);
    printk("--------------------\n");
}

uint16_t calc_cksum(unsigned char* data, uint16_t orig_sum, int size)
{
    uint32_t sum = orig_sum;
    uint16_t *ptr = (uint16_t*)data;
    int rest;

    for(rest = size; rest > 1; rest -= 2)
    {
        sum += *ptr;
        if(sum > 0xFFFF)
            sum = (sum & 0xFFFF) + (sum >> 16);
        ptr++;
    }
    if(rest == 1)
    {
        uint16_t val = 0;
        memcpy(&val, ptr, sizeof(uint8_t));
        sum += val;
    }
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)~sum;
}

struct pseudo_ipv4_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  ptcl;
    uint16_t length;
};

uint16_t calc_pseudo_ipv4_header(unsigned char* ip_hdr)
{
    struct pseudo_ipv4_header pseudo_hdr;
    uint16_t sum;
    uint16_t tcp_length = ntohs(*(uint16_t*)(ip_hdr + 2)) - (((*(uint8_t*)(ip_hdr)) & 0x0F) * 4);

    // Pseudo IPv4 header
    memcpy(&pseudo_hdr.src_addr, (ip_hdr + 12), 4);
    memcpy(&pseudo_hdr.dst_addr, (ip_hdr + 16), 4);
    pseudo_hdr.zero = 0;
    pseudo_hdr.ptcl = 6; // 6: TCP
    pseudo_hdr.length = htons(tcp_length);
    sum = calc_cksum((unsigned char*)&pseudo_hdr, 0, sizeof(pseudo_hdr));
    dump_data((unsigned char*)&pseudo_hdr, sizeof(pseudo_hdr));

    return sum;
}

struct neighbour * get_neighbour(struct sk_buff *skb)
{
    struct neighbour *neigh;
    struct dst_entry *dst = skb_dst(skb);
    struct rtable *rt = (struct rtable *)dst;
    struct net_device *dev = dst->dev;

    uint32_t nexthop;
    if(rt->rt_gateway)
        nexthop = (uint32_t)rt->rt_gateway;
    else
        nexthop = (uint32_t)ip_hdr(skb)->daddr;
    skb->dev = dev;

    neigh = __ipv4_neigh_lookup_noref(dev, nexthop);

    return neigh;
}

unsigned int main_hook
(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
)
{
    struct tcphdr *tcp_header;
    struct iphdr *ip_header;
    struct sk_buff *new_skb;

    /* Read socket buffer */
    if(skb == NULL)
    {
        return NF_ACCEPT; /* Pass */
    }
    /* Confirm IP header */
    ip_header = ip_hdr(skb);
    if(!ip_header)
    {
        return NF_ACCEPT; /* Pass */
    }
    /* Confirm destination IP address in IP header */
    if(be32_to_cpu(ip_header->daddr) != DST_IP_ADDRESS)
    {
        return NF_ACCEPT; /* Pass */
    }
    /* Confirm IP protocol number */
    if(ip_header->protocol != IPPROTO_TCP) /* Except TCP */
    {
        return NF_ACCEPT; /* Pass */
    }
    /* Read TCP header */
    tcp_header = tcp_hdr(skb);
    /* Confirm destination port number in TCP header */
    if(be16_to_cpu(tcp_header->source) == PORT_NUMBER)
    {
#if HOOK_PACKET_DROP
        return NF_DROP;
#else
        struct neighbour *neigh;
        int num_skb = 1;
        uint16_t pseudo_sum;
        /* Scatter/Gather func. check */
#if 0
        if(!(skb->sk->sk_route_caps & NETIF_F_SG))
        {
            skb->sk->sk_route_caps |= NETIF_F_SG;
            printk("Scatter/Gather -> ON\n");
        }
#endif
        /* GSO func. check */
        struct tcp_sock *tp = tcp_sk(skb->sk);
#if DEBUG_PRINT
        printk("--------------------------\n");
        printk("socket sk_route_caps: %llx\n", skb->sk->sk_route_caps);
        printk("socket gso type: %d\n", skb->sk->sk_gso_type);
        printk("socket gso max size: %d\n", skb->sk->sk_gso_max_size);
        printk("socket gso max segs: %u\n", skb->sk->sk_gso_max_segs);
        //printk("netdev gso max size: %d\n", in->gso_max_size);
        //printk("netdev gso max segs: %u\n", in->gso_max_segs);
        if(skb->dev)
        {
            printk("netdev gso max size: %d\n", skb->dev->gso_max_size);
            printk("netdev gso max segs: %u\n", skb->dev->gso_max_segs);
        }
        printk("shinfo gso size: %u\n", skb_shinfo(skb)->gso_size);
        printk("shinfo gso segs: %u\n", skb_shinfo(skb)->gso_segs);
        printk("shinfo gso type: %u\n", skb_shinfo(skb)->gso_type);
        printk("shinfo nr frags: %d\n", skb_shinfo(skb)->nr_frags);
        //printk("tcp current mss: %u\n", tcp_current_mss(skb->sk));
        printk("tcp mss cache: %u\n", tp->mss_cache);
        printk("tcp gso_segs: %u\n", tp->gso_segs);
        printk("NETIF_F_GSO_SHIFT: %d\n", NETIF_F_GSO_SHIFT);
        //dump_data(skb->data, 40);
#endif
#if 1
        if(!(skb->sk->sk_route_caps & (1 << NETIF_F_GSO_SHIFT)))
        {
            //netif_set_gso_max_size(in, 16*1460);
            skb->sk->sk_gso_max_size = 16*1460;
            skb->sk->sk_gso_max_segs = 16;
            tp->mss_cache = 16*1460;
            tp->gso_segs = 16;
            skb->sk->sk_route_caps |= (1 << NETIF_F_GSO_SHIFT);
            printk("GSO -> ON\n");
            printk("data_len: %u\n", skb->data_len);
            printk("len: %u\n", skb->len);
            num_skb = (skb->len - 40) / 1460;
            if((skb->len - 40) % 1460)
                num_skb++;
            printk("num_skb: %d\n", num_skb);
            printk("skb->ip_summed: %d\n", skb->ip_summed);
        }
#endif

        neigh = get_neighbour(skb);
        if(neigh) {
            int hh_len, hh_alen;
            skb->protocol = htons(ETH_P_IP);
#if !RASPI_CKSUM_OFFLOAD
            // Calc IP checksum
            printk("existed IP cksum: %02x\n", ntohs(ip_header->check));
            ip_header->check = 0;
            ip_header->check = calc_cksum((unsigned char*)ip_header, 0, 20);
            printk("Recalc IP cksum: %02x\n", ntohs(ip_header->check));
            // Calc TCP checksum
            // Existed TCP cksum value is calculated only part of pseudo IPv4 header.
            printk("existed TCP cksum: %02x\n", ntohs(tcp_header->check));
            tcp_header->check = 0;
            pseudo_sum = calc_pseudo_ipv4_header((unsigned char*)ip_header);
            printk("Recalc TCP cksum: %02x\n", (uint16_t)~(ntohs(pseudo_sum)));
            tcp_header->check = calc_cksum(skb->data + 20, ~(pseudo_sum), skb->len - 20); 
            printk("TCP cksum: %02x\n", ntohs(tcp_header->check));
            //dump_data(skb->data + 20, skb->len - 20);
#endif /* !RASPI_CKSUM_OFFLOAD */
            print_skb_info(skb);
            // Segment Jumbo frame
            if(skb->len > 1500) {
                skb->len = 1500;
                skb->tail = skb->data + 1500;
                ip_header->tot_len = htons(1500);
                // Recalc IP checksum
                ip_header->check = 0;
                ip_header->check = calc_cksum((unsigned char*)ip_header, 0, 20);
                // Recalc TCP checksum
                tcp_header->check = 0;
#if !RASPI_CKSUM_OFFLOAD
                pseudo_sum = calc_pseudo_ipv4_header((unsigned char*)ip_header);
                tcp_header->check = calc_cksum(skb->data + 20, ~(pseudo_sum), skb->len - 20); 
#else
                tcp_header->check = calc_pseudo_ipv4_header((unsigned char*)ip_header);
                printk("recalc tcp cksum: %02x\n", tcp_header->check);
#endif
            }
            // Create MAC header
            hh_len = neigh->hh.hh_len;
            hh_alen = HH_DATA_ALIGN(hh_len);
            printk("hh_len: %d\n", hh_len);
            printk("hh_alen: %d\n", hh_alen);
            printk("hh->data >\n");
            dump_data(neigh->hh.hh_data, hh_alen);
            memcpy(skb->data - hh_alen, neigh->hh.hh_data, hh_alen);
            skb_push(skb, hh_len);
            // Transmit sk_buff
            dev_queue_xmit(skb);
            return NF_STOLEN;
        }
        else {
            printk("Neighbour is not existed yet.\n");
        }
#endif /* HOOK_PACKET_DROP */
    }

    return NF_ACCEPT; /* Pass */
}

/* Initialize routine called when module is loaded. */
static int hookmod_init_module(void)
{
    int error = 0;
    /*
     * Initialize operation
     */
    printk("hook_mod is loaded.\n");
    /*
     * Error handling
     */
    if(error)
        return -ENODEV;

    /* Hook condition */
    netfilter_ops_in.hook = main_hook;
    netfilter_ops_in.pf = PF_INET;
#if (HOOK_MODE == RECV_MODE)
    netfilter_ops_in.hooknum = NF_INET_LOCAL_IN; /* input */
#else
    netfilter_ops_in.hooknum = NF_INET_LOCAL_OUT; /* output */
#endif
    netfilter_ops_in.priority = NF_IP_PRI_FIRST; /* First priority */

    /* Register hook API to NetFilter */
    nf_register_hook(&netfilter_ops_in);
    printk(KERN_INFO "Packet Hook: loaded\n");

    return 0;
}

/* Cleanup routine called when module is unloaded. */
static void hookmod_cleanup_module(void)
{
    printk("hook_mod is unloaded.\n");
    /* Unregister hook API to NetFilter */
    nf_unregister_hook(&netfilter_ops_in);
    printk(KERN_INFO "Packet Hook: unloaded\n");
}

module_init(hookmod_init_module);
module_exit(hookmod_cleanup_module);

