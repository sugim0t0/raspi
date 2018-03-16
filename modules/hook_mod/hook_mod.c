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

#define RECV_MODE 0
#define SEND_MODE 1
//#define HOOK_MODE RECV_MODE
#define HOOK_MODE SEND_MODE

#if (HOOK_MODE == RECV_MODE)
/* 172.29.46.215 */
#define DST_IP_ADDRESS 0xAC1D2ED7
#else
/* 172.29.47.105 */
#define DST_IP_ADDRESS 0xAC1D2F69
#endif
#define PORT_NUMBER 12345

#define DEBUG_PRINT 1

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

uint16_t calc_ip_cksum(unsigned char* ip_hdr)
{
    int i;
    uint32_t result = 0;
    uint16_t *offset = (uint16_t*)ip_hdr;
    for(i=0; i<10; i++)
    {
        if(i != 5) // Ignore existed checksum value
        {
            result += *offset;
            if(result > 0xFFFF)
            {
                result &= 0xFFFF;
                result++;
            }
        }
        offset++;
    }
    return (uint16_t)(~result & 0xFFFF);
}

uint16_t calc_tcp_cksum(unsigned char* tcp_hdr, unsigned char* ip_hdr)
{
    int i;
    uint32_t result = 0;
    uint16_t *offset;
    uint16_t protocol = 6;
    uint16_t length = ntohs(*(uint16_t*)(ip_hdr + 2));
    printk("length: %d\n", length);
    length -= 20; // 20: Length of IP header
    // pseudo header
    offset = (uint16_t*)(ip_hdr + 12);
    for(i=0; i<4; i++)
    {
        result += *offset;
        if(result > 0xFFFF)
        {
            result &= 0xFFFF;
            result++;
        }
        offset++;
    }
    //result += htons(protocol);
    //result += protocol;
    if(result > 0xFFFF)
    {
        result &= 0xFFFF;
        result++;
    }
    //result += htons(length);
    //result += length;
    if(result > 0xFFFF)
    {
        result &= 0xFFFF;
        result++;
    }
    // TCP header + payload
    offset = (uint16_t*)tcp_hdr;
    for(i=0; i<(length/2); i++)
    {
        if(i != 8) // Ignore existed checksum value
        {
            result += *offset;
            if(result > 0xFFFF)
            {
                result &= 0xFFFF;
                result++;
            }
        }
        offset++;
    }
    return (uint16_t)(~result & 0xFFFF);
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
        int num_skb;
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
        dump_data(skb->data, 40);
#endif
        if(!(skb->sk->sk_route_caps & (1 << NETIF_F_GSO_SHIFT)))
        {
            //netif_set_gso_max_size(in, 16*1460);
            skb->sk->sk_gso_max_size = 16*1460;
            skb->sk->sk_gso_max_segs = 16;
            tp->mss_cache = 16*1460;
            tp->gso_segs = 16;
            skb->sk->sk_route_caps |= (1 << NETIF_F_GSO_SHIFT);
            printk("GSO -> ON\n");
        }
        printk("data_len: %u\n", skb->data_len);
        printk("len: %u\n", skb->len);
        num_skb = (skb->len - 40) / 1460;
        if((skb->len - 40) % 1460)
            num_skb++;
        printk("num_skb: %d\n", num_skb);
#if 0
        if(skb->len > 1500)
        {
            printk("IP len:%u\n", ip_header->tot_len);
            ip_header->tot_len = htons(1500);
            skb->len = 1500;
            skb->tail = skb->data + 1500;
        }
#endif
        printk("IP cksum: %u\n", ip_header->check);
        printk("recalc IP cksum: %u\n", calc_ip_cksum((unsigned char*)ip_header));
        printk("TCP cksum: %u\n", tcp_header->check);
        printk("recalc TCP cksum: %u\n", calc_tcp_cksum((unsigned char*)tcp_header, (unsigned char*)ip_header));
#if 0
        if(num_skb > 1)
        {
            int i;
            for(i=0; i<num_skb; i++)
            {
                new_skb = __alloc_skb(1500, skb->sk->allocation, SKB_ALLOC_FCLONE, NUMA_NO_NODE);
                if(!new_skb)
                {
                    new_skb->
                }
            }
#endif
#if 0
            ip_header->tot_len = 1500;
            skb->len = 1500;
            skb->tail = skb->data + 1500;
            return NF_ACCEPT;
        }
        else
        {
            return NF_ACCEPT; /* Pass */
        }
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

