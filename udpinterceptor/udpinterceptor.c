#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/vmalloc.h>
 
#include <linux/netfilter_ipv4.h>
 
MODULE_LICENSE("GPL");
 
static struct nf_hook_ops nfho;
 
unsigned int my_hook(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    struct iphdr *network_header;
    struct udphdr *udp_header; 
    int sport, dport;
 
    // Get IP header
    network_header = (struct iphdr *)skb_network_header(skb);
 
    // Intercept UDP ports
    if (network_header->protocol == IPPROTO_UDP) {
        // Get UDP Header
        udp_header = (struct udphdr *)skb_transport_header(skb);
 
        // Get and cast UDP destination port
        dport = ntohs((unsigned short int) udp_header->dest);
 
        // Get and cast UDP source port
        sport = ntohs((unsigned short int) udp_header->source);
 
        // Print destination
        printk("Received UDP datagram from %pI4 port %d destined to port %d!\n",
            &network_header->saddr,
            sport,
            dport);
    }
 
    // Let the message through
    return NF_ACCEPT;
}
 
static int init_filter_if(void)
{
    nfho.hook = my_hook;
    nfho.hooknum = 0 ; //NF_IP_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
  
    nf_register_hook(&nfho);
  
    return 0;
}
 
static int __init udpinterceptor_init(void)
{
    printk(KERN_INFO "Loading UDP listener!\n");
    init_filter_if();
    return 0;
}
 
static void __exit udpinterceptor_cleanup(void)
{
    nf_unregister_hook(&nfho);
    printk(KERN_INFO "Cleaning up UDP listener\n");
}
 
module_init(udpinterceptor_init);
module_exit(udpinterceptor_cleanup);
