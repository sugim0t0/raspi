/**
 * Send packets hook module by netfilter
 * This module segments IP jumbo frame packet.
 * And creates TCP/IP/Mac headers from original IP packet.
 *
 * Test Linux kernel version: 4.9.80
 *
 * @author Sugimoto
 * @version 0.1
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/mm.h>
#include <net/arp.h>
#include <net/route.h>
#include <net/sock.h>

/* 172.29.46.135 */
#define DST_IP_ADDRESS 0xAC1D2E87
#define PORT_NUMBER         12345

#define HOOK_PACKET_DROP        0
#define DEBUG_PRINT             1
#define CKSUM_PRINT             0

#define TCP_PTCL_NUMBER         6
#define SIZE_OF_TCP_HDR        20
#define SIZE_OF_IP_HDR         20
#define LOCAL_MSS            1460
#define MAX_NUM_OF_PKT         16

/* IP jumbo frame mode */
#define NO_JUMBO_MODE 0
#define FAKE_MSS_MODE 1
#define SG_GSO_MODE   2
//#define JUMBO_FRAME_MODE NO_JUMBO_MODE
//#define JUMBO_FRAME_MODE FAKE_MSS_MODE
#define JUMBO_FRAME_MODE SG_GSO_MODE /* SG_GSO_MODE is very slow now! 2018.05.16 */

MODULE_DESCRIPTION("Send packets hook module by netfilter");
MODULE_AUTHOR("Sugimoto");
MODULE_LICENSE("GPL");

/**
 * Structure of pseudo IPv4 header for TCP checksum calculation
 */
struct pseudo_ipv4_header
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  ptcl;
    uint16_t length;
};

/* static variable */
static struct nf_hook_ops netfilter_ops_in;

/**
 * Functions
 */
/**
 * Dump data
 * @param *data : start pointer for dump
 * @param size  : size of dump data (bytes)
 */
void dump_data(unsigned char* data, int size)
{
    int i;
    for(i = 0; i < size; i++)
    {
        printk("[%d]%02x", i, *(data + i));
    }
}

/**
 * Print information of sk_buff
 * @param *skb : sk_buff
 */
void print_skb_info(struct sk_buff *skb)
{
    printk("---- SKBUF info ----\n");
    printk("len:       %u\n", skb->len);
    printk("data_len:  %u\n", skb->data_len);
    if(skb->data_len > 0 && skb->end != NULL)
    {
        struct skb_shared_info *sh = (struct skb_shared_info *)skb->end;
        struct sk_buff *skb_frag;
        int n;
        unsigned long pageaddr;
        printk("    == SKB_SHARED_INFO ==\n");
        printk("    nr_frags:  %u\n", sh->nr_frags);
        printk("    gso_size:  %u\n", sh->gso_size);
        printk("    gso_segs:  %u\n", sh->gso_segs);
        skb_frag = sh->frag_list;
        while(skb_frag)
        {
            printk("    frag_list[%d] len: %u\n", n++, skb_frag->len);
            skb_frag = skb_frag->next;
        }
        for(n = 0; n < MAX_SKB_FRAGS; n++)
        {
            if(sh->frags[n].size == 0)
                break;
            printk("    frags[%d] size:         %u\n", n, sh->frags[n].size);
            pageaddr = (unsigned long)page_address(sh->frags[n].page.p);
            printk("    frags[%d] page address: %lx\n", n, pageaddr);
            printk("    frags[%d] page offset:  %u\n", n, sh->frags[n].page_offset);
            dump_data((unsigned char *)(pageaddr + sh->frags[n].page_offset), 10);
        }
        printk("    =====================\n");
    }
    printk("head addr: %p\n", skb->head);
    printk("data addr: %p\n", skb->data);
    printk("tail addr: %p\n", skb->tail);
    printk("end addr:  %p\n", skb->end);
#if CKSUM_PRINT
    printk("csum:      %u\n", skb->csum);
    printk("ip_summed: %d\n", skb->ip_summed);
#endif
    printk("--------------------\n");
}

/**
 * Print information of IP header
 * @param *hdr : IP header
 */
void print_ip_hdr(struct iphdr *hdr)
{
    printk("---- IP header -----\n");
    printk("len:   %u\n", ntohs(hdr->tot_len));
    printk("check: %02x\n", ntohs(hdr->check));
    printk("--------------------\n");
}

/**
 * Print information of offload functions
 * @param *skb : sk_buff
 */
void print_offload_func(struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(skb->sk);
    printk("-- Offload func. ---\n");
    printk("socket sk_route_caps: %llx\n", skb->sk->sk_route_caps);
    if(sk_can_gso(skb->sk))
        printk("can gso\n");
    else
        printk("cannot gso\n");
    printk("socket gso type: %d\n", skb->sk->sk_gso_type);
    printk("socket gso max size: %d\n", skb->sk->sk_gso_max_size);
    printk("socket gso max segs: %u\n", skb->sk->sk_gso_max_segs);
    if(skb->dev)
    {
        printk("netdev gso max size: %d\n", skb->dev->gso_max_size);
        printk("netdev gso max segs: %u\n", skb->dev->gso_max_segs);
    }
    printk("shinfo gso size: %u\n", skb_shinfo(skb)->gso_size);
    printk("shinfo gso segs: %u\n", skb_shinfo(skb)->gso_segs);
    printk("shinfo gso type: %u\n", skb_shinfo(skb)->gso_type);
    printk("shinfo nr frags: %d\n", skb_shinfo(skb)->nr_frags);
    printk("tcp mss cache: %u\n", tp->mss_cache);
    printk("tcp gso_segs: %u\n", tp->gso_segs);
    printk("NETIF_F_GSO_SHIFT: %d\n", NETIF_F_GSO_SHIFT);
    printk("--------------------\n");
}

/**
 * Calculate checksum
 * @param *data : start pointer of calculation
 * @param orig_sum : start sum value to be added
 * @param size : size of data to be calculated
 * @return calculated sum value
 */
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

/**
 * Calculate pseudo IPv4 header
 * @param *ip_hdr : IPv4 header
 * @return calculated sum value
 */
uint16_t calc_pseudo_ipv4_header(unsigned char* ip_hdr)
{
    struct pseudo_ipv4_header pseudo_hdr;
    uint16_t sum;
    uint16_t tcp_length = ntohs(*(uint16_t*)(ip_hdr + 2)) - (((*(uint8_t*)(ip_hdr)) & 0x0F) * 4);

    // Pseudo IPv4 header
    memcpy(&pseudo_hdr.src_addr, (ip_hdr + 12), 4);
    memcpy(&pseudo_hdr.dst_addr, (ip_hdr + 16), 4);
    pseudo_hdr.zero = 0;
    pseudo_hdr.ptcl = TCP_PTCL_NUMBER;
    pseudo_hdr.length = htons(tcp_length);
    sum = calc_cksum((unsigned char*)&pseudo_hdr, 0, sizeof(pseudo_hdr));
    //dump_data((unsigned char*)&pseudo_hdr, sizeof(pseudo_hdr));

    return sum;
}

/**
 * Set checksums for TCP/IP in each header
 * @param *skb : sk_buff
 */
void set_tcp_ip_cksum(struct sk_buff *skb)
{
    struct tcphdr *tcp_header = tcp_hdr(skb);
    struct iphdr *ip_header = ip_hdr(skb);
    uint16_t pseudo_sum;

    // Calc IP checksum
    ip_header->check = 0;
    ip_header->check = calc_cksum((unsigned char*)ip_header, 0, SIZE_OF_IP_HDR);
    // Calc TCP checksum
    tcp_header->check = 0;
    pseudo_sum = calc_pseudo_ipv4_header((unsigned char*)ip_header);
    tcp_header->check = calc_cksum(skb->data + SIZE_OF_IP_HDR, ~(pseudo_sum), skb->len - SIZE_OF_IP_HDR);
#if CKSUM_PRINT
    printk("TCP checksum: %02x\n", ntohs(tcp_header->check));
#endif
    // Set CHECKSUM_COMPLETE to ip_summed for disabling H/W checksum offload.
    skb->ip_summed = CHECKSUM_COMPLETE;
}

/**
 * Get neighbour (ARP entry)
 * @param *skb : sk_buff
 * @return neighbour
 */
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

/**
 * Set configurations for IP jumbo frame
 * To Be Confirmed which parameters are valid!
 * @param *skb : sk_buff
 */
void set_jumbo_frame(struct sk_buff *skb)
{
    struct tcp_sock *tp = tcp_sk(skb->sk);
#if JUMBO_FRAME_MODE == FAKE_MSS_MODE
    tp->mss_cache = MAX_NUM_OF_PKT * LOCAL_MSS;
#elif JUMBO_FRAME_MODE == SG_GSO_MODE
    //netif_set_gso_max_size(in, 16*1460);
    skb->sk->sk_gso_max_size = MAX_NUM_OF_PKT * LOCAL_MSS;
    skb->sk->sk_gso_max_segs = MAX_NUM_OF_PKT;
    tp->gso_segs = MAX_NUM_OF_PKT;
    skb->sk->sk_route_caps |= (1 << NETIF_F_GSO_SHIFT);
#if DEBUG_PRINT
    printk("GSO -> ON\n");
#endif
    if(!(skb->sk->sk_route_caps & NETIF_F_SG))
    {
        skb->sk->sk_route_caps |= NETIF_F_SG;
    }
#if DEBUG_PRINT
    printk("Scatter/Gather -> ON\n");
#endif
#endif
    // 2018.05.10 Test
#if 0
    skb->dev->gso_partial_features |= NETIF_F_GSO_PARTIAL | NETIF_F_GSO_IPXIP4;
    skb->dev->features |= NETIF_F_GSO_PARTIAL | NETIF_F_GSO_IPXIP4;
#endif
}

/**
 * Allocate new sk_buff for fragment packet
 * @param *skb : original sk_buff
 * @return allocated new sk_buff
 */
struct sk_buff * alloc_new_skb(struct sk_buff *skb)
{
    struct sk_buff *new_skb;
    uint32_t skb_size = LOCAL_MSS + skb->sk->sk_prot->max_header;

    new_skb = alloc_skb(skb_size, GFP_ATOMIC);
    if(new_skb == NULL)
    {
        printk(KERN_WARNING "alloc new skb failed");
        return NULL;
    }
#if DEBUG_PRINT
    printk("alloc new skb successed\n");
#endif
    new_skb->protocol = htons(ETH_P_IP);
    skb_put(new_skb, skb_size);
    new_skb->data += skb->sk->sk_prot->max_header;
    new_skb->tail += skb->sk->sk_prot->max_header;
    new_skb->dev = skb->dev;
    new_skb->protocol = skb->protocol;
    new_skb->mac_len = skb->mac_len;
    new_skb->transport_header = (new_skb->data - SIZE_OF_TCP_HDR) - new_skb->head;
    new_skb->network_header = (new_skb->data - (SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR)) - new_skb->head;

    return new_skb;
}

/**
 * Create TCP packet
 * 1) copy TCP payload and TCP/IP header from original sk_buff
 * 2) update TCP sequence number
 * @param *org_skb : original sk_buff
 * @param *skb : created TCP packet sk_buff
 * @param offset : payload offset from head of payload in original sk_buff
 * @param len : length of payload (bytes)
 * @param seq : TCP sequence number of original sk_buff
 */
void create_tcp_packet
(
    struct sk_buff *org_skb,
    struct sk_buff *skb,
    uint32_t offset,
    int len,
    uint32_t seq
)
{
    struct tcphdr *tcp_header;
    unsigned char *payload = org_skb->data + SIZE_OF_IP_HDR + SIZE_OF_TCP_HDR;
    unsigned char *template_header = org_skb->data;
    uint32_t local_offset = offset;
    int n;
    int copied_len = 0;
    int inner_data_len = org_skb->len - (org_skb->data_len + SIZE_OF_IP_HDR + SIZE_OF_TCP_HDR);
    struct skb_shared_info *sh = (struct skb_shared_info *)org_skb->end;
    unsigned long pageaddr;
    int copy_len;

#if DEBUG_PRINT
    printk("-- Create TCP packet --\n");
    printk("size:   %d\n", len);
    printk("seq:    %x\n", seq + offset);
    printk("offset: %u\n", offset);
#endif
    // copy TCP payload from original sk_buff
    if(inner_data_len > 0)
    {
        if(offset < inner_data_len)
        {
            copied_len = (len > (inner_data_len - offset))? (inner_data_len - offset) : len;
            memcpy(skb->data, (payload + offset), copied_len);
            local_offset -= copied_len;
        }
        else
        {
            local_offset -= inner_data_len;
        }
    }
    // copy TCP payload from pages
    for(n = 0; len > copied_len && n < MAX_SKB_FRAGS; n++)
    {
        if(local_offset > sh->frags[n].size)
        {
            local_offset -= sh->frags[n].size;
            copied_len += sh->frags[n].size;
            continue;
        }
        pageaddr = (unsigned long)page_address(sh->frags[n].page.p);
        copy_len = ((sh->frags[n].size - local_offset) > (len - copied_len))? (len - copied_len) : (sh->frags[n].size - local_offset);
#if DEBUG_PRINT
        printk("    == Copy payload from page (frags[%d]) ==\n", n);
        printk("    page addr:    %lx\n", pageaddr);
        printk("    page size:    %u\n", sh->frags[n].size);
        printk("    page offset:  %u\n", sh->frags[n].page_offset);
        printk("    local offset: %u\n", local_offset);
        printk("    copy size:    %d\n", copy_len);
        printk("    =======================================\n");
#endif
        memcpy((skb->data + copied_len), (unsigned char *)pageaddr + sh->frags[n].page_offset + local_offset, copy_len);
        copied_len += copy_len;
        local_offset = 0;
    }
    // copy TCP/IP header from template header
    memcpy(skb->data - (SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR), template_header, (SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR));
    skb->data -= (SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR);
    skb->len = len + SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR;
    // update TCP sequence number
    tcp_header = tcp_hdr(skb);
    tcp_header->seq = htonl(seq + offset);
#if DEBUG_PRINT
    printk("-----------------------\n");
#endif
}

/**
 * Create MAC header
 * @param *neigh : neighbour
 * @param *skb : sk_buff
 */
void create_mac_header(struct neighbour *neigh, struct sk_buff *skb)
{
    int hh_len = neigh->hh.hh_len;
    int hh_alen = HH_DATA_ALIGN(hh_len);
#if CKSUM_PRINT
    printk("hh_len (length of MAC header): %d\n", hh_len);
    printk("hh_alen (aligned length of MAC header): %d\n", hh_alen);
    printk("hh->data >\n");
    dump_data((unsigned char *)neigh->hh.hh_data, hh_alen);
#endif
    memcpy(skb->data - hh_alen, neigh->hh.hh_data, hh_alen);
    skb_push(skb, hh_len);
}

/**
 * Operation for hook packet
 * @param *skb : hooked packet
 * @return result of handling hook packet
 */
int hook_packet(struct sk_buff *skb)
{
    struct neighbour *neigh;
#if JUMBO_FRAME_MODE == SG_GSO_MODE
    struct sock *sk = skb->sk;
#endif
    uint32_t seq = ntohl(tcp_hdr(skb)->seq);
    uint32_t payload_offset = 0;
    uint16_t payload_len = 0;
    int16_t xmit_val = 0;
    int rest_data = skb->len - (SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR);
    struct sk_buff *xmit_skb = NULL;

#if DEBUG_PRINT
    print_skb_info(skb);
    print_offload_func(skb);
#endif

#if JUMBO_FRAME_MODE == SG_GSO_MODE
    if(!(sk->sk_route_caps & (1 << NETIF_F_GSO_SHIFT)))
        set_jumbo_frame(skb);
#elif JUMBO_FRAME_MODE == FAKE_MSS_MODE
    set_jumbo_frame(skb);
#endif

    if(rest_data <= LOCAL_MSS)
        return NF_ACCEPT;

    neigh = get_neighbour(skb);
    if(neigh == NULL)
    {
        printk(KERN_WARNING "Neighbour is not existed yet.");
        return NF_ACCEPT;
    }

    while(rest_data > 0)
    {
        // Alloc new sk_buff
        xmit_skb = alloc_new_skb(skb);
        if(xmit_skb == NULL)
            return NF_DROP;
        // Create TCP packet
        payload_len = (rest_data > LOCAL_MSS)? LOCAL_MSS : rest_data;
        create_tcp_packet
        (
            skb,
            xmit_skb,
            payload_offset,
            payload_len,
            seq
        );
        xmit_skb->len = payload_len + SIZE_OF_TCP_HDR + SIZE_OF_IP_HDR;
        rest_data -= payload_len;
        payload_offset += payload_len;
        xmit_skb->tail = xmit_skb->data + xmit_skb->len;
        // Change IP frame length in IP header
        ip_hdr(xmit_skb)->tot_len = htons(xmit_skb->len);
        // Calc and Set TCP/IP checksum
        set_tcp_ip_cksum(xmit_skb);
        // Create MAC header
        create_mac_header(neigh, xmit_skb);
        // Transmit sk_buff
        xmit_val = dev_queue_xmit(xmit_skb);
        if(xmit_val != NET_XMIT_SUCCESS)
        {
            printk(KERN_WARNING "failed to send packet : xmit return value=%d", xmit_val);
        }
        // Delete allocated sk_buff
    }

    return NF_STOLEN;
}

/**
 * Hook function (called from nf_hook() in include/linux/netfilter.h)
 */
unsigned int main_hook
(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
)
{
    struct tcphdr *tcp_header;
    struct iphdr *ip_header;

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
        return hook_packet(skb);
#endif
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
    netfilter_ops_in.hooknum = NF_INET_LOCAL_OUT; /* output */
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

