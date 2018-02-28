/*
 * hook_mod.c
 * Send/Recv packets hook module by netfilter
 * Test Linux kernel version: 4.9.80
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

MODULE_DESCRIPTION("Send/Recv packets hook module by netfilter");
MODULE_AUTHOR("sugimoto");
MODULE_LICENSE("GPL");

/* static variable */
static struct nf_hook_ops netfilter_ops_in;

/* function */
unsigned int main_hook
(
    const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff*)
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
        printk("data_len: %u\n", skb->data_len);
        printk("len: %u\n", skb->len);
        return NF_ACCEPT; /* Pass */
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

