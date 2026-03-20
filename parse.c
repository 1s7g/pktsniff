#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include "parse.h"


// returns ethertype so main can decide what to do
int print_ethernet(unsigned char* buf, int size)
{
    if(size < 14) {
        printf("  [ETH] packet too small??\n");
        return -1;
    }

    struct ethhdr *eth = (struct ethhdr *)buf;

    printf("  [ETH] %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5],
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    unsigned short proto = ntohs(eth->h_proto);
    if(proto == 0x0800) printf("  (IPv4)");
    else if(proto == 0x0806) printf("  (ARP)");
    else if(proto == 0x86DD) printf("  (IPv6)");
    else printf("  (0x%04x)", proto);
    printf("\n");

    return proto;
}



void process_ip_packet(unsigned char *buf, int size, int *tcp_cnt, int *udp_cnt, int *icmp_cnt, int *other_cnt)
{
    struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));

    if(size < sizeof(struct ethhdr) + sizeof(struct iphdr)){
        printf("  [IP] truncated\n");
        return;
    }

    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    char srcip[16], dstip[16];
    strcpy(srcip, inet_ntoa(src));
    strcpy(dstip, inet_ntoa(dst));

    printf("  [IP]  %s -> %s  ttl=%d", srcip, dstip, ip->ttl);

    int proto = ip->protocol;
    int iphdrlen = ip->ihl * 4;
    int header_offset = sizeof(struct ethhdr) + iphdrlen;

    if(proto == 6)
    {
        printf("  proto=TCP\n");
        (*tcp_cnt)++;

        struct tcphdr *tcp = (struct tcphdr *)(buf + header_offset);
        printf("  [TCP] port %d -> %d", ntohs(tcp->source), ntohs(tcp->dest));

        printf("  [");
        if(tcp->syn) printf("S");
        if(tcp->ack) printf("A");
        if(tcp->fin) printf("F");
        if(tcp->rst) printf("R");
        if(tcp->psh) printf("P");
        printf("]");
        printf("  seq=%u\n", ntohl(tcp->seq));
    }
    else if(proto == 17)
    {
        printf("  proto=UDP\n");
        (*udp_cnt)++;

        struct udphdr* udp = (struct udphdr *)(buf + header_offset);
        printf("  [UDP] port %d -> %d  len=%d\n",
            ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
    }
    else if(proto == 1)
    {
        printf("  proto=ICMP\n");
        (*icmp_cnt)++;

        struct icmphdr *icmp = (struct icmphdr*)(buf + header_offset);

        printf("  [ICMP] ");
        switch(icmp->type){
            case 8: printf("Echo Request"); break;
            case 0: printf("Echo Reply"); break;
            case 3: printf("Dest Unreachable"); break;
            case 11: printf("TTL Exceeded"); break;
            default: printf("type=%d", icmp->type);
        }
        printf("\n");
    }
    else
    {
        printf("  proto=%d\n", proto);
        (*other_cnt)++;
    }
}


void process_arp(unsigned char *buf, int len)
{
    unsigned char *arp = buf + 14;

    int opcode = (arp[6] << 8) + arp[7];

    printf("  [ARP] ");
    if(opcode == 1) printf("REQUEST");
    else if(opcode == 2) printf("REPLY  ");
    else printf("op=%d", opcode);

    // sender ip offset 14, target ip offset 24
    // wait i think its 14 from arp start... 
    // 8 byte header + 6 byte mac = 14... yeah
    printf("  %d.%d.%d.%d", arp[14], arp[15], arp[16], arp[17]);
    printf(" -> ");
    printf("%d.%d.%d.%d", arp[24], arp[25], arp[26], arp[27]);

    printf("  [%02x:%02x:%02x:%02x:%02x:%02x]",
        arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]);
    printf("\n");
}