// pktsniff

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <signal.h>

int pktcount = 0;
int sock_raw;
int tcp_count, udp_count, icmp_cnt = 0;
int arp_cnt = 0;
int ipv6cnt;
int other = 0;
int show_hexdump = 1;    // might add flag for this later

// for debugging earlier, keeping just in case
int last_packet_size = 0;


void cleanup(int sig){
    printf("\n\n");
    printf("  --- stats ---\n");
    printf("  total:  %d\n", pktcount);
    printf("  tcp:    %d\n", tcp_count);
    printf("  udp:    %d\n", udp_count);
    printf("  icmp:   %d\n", icmp_cnt);
    printf("  arp:    %d\n", arp_cnt);
    printf("  ipv6:   %d\n", ipv6cnt);
    printf("  other:  %d\n", other);
    printf("\n");
    close(sock_raw);
    exit(0);
}

// https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
void hexdump(unsigned char *buf, int len)
{
    int i, j;

    for(i = 0; i < len; i++)
    {
        if(i % 16 == 0)
        {
            if(i != 0)
            {
                printf("  ");
                for(j = i-16; j < i; j++)
                {
                    if(buf[j] > 31 && buf[j] < 127)
                        printf("%c", buf[j]);
                    else
                        printf(".");
                }
                printf("\n");
            }
            printf("  %04x  ", i);
        }
        printf(" %02x", buf[i]);
    }

    int leftover = len % 16;
    if(leftover == 0) leftover = 16;

    if(leftover != 16) {
        int x;
        for(x = 0; x < (16 - leftover); x++)
            printf("   ");
    }
    printf("  ");
    for(j = len - leftover; j < len; j++){
        if(buf[j] > 31 && buf[j] < 127)
            printf("%c", buf[j]);
        else printf(".");
    }
    printf("\n");
}


void print_ethernet(unsigned char* buf, int size)
{
    // need at least 14 bytes for eth header
    if(size < 14) {
        printf("  [ETH] packet too small??\n");
        return;
    }

    struct ethhdr *eth = (struct ethhdr *)buf;

    printf("  [ETH] %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0], eth->h_source[1], eth->h_source[2],
        eth->h_source[3], eth->h_source[4], eth->h_source[5],
        eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
        eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    // ethertype
    unsigned short proto = ntohs(eth->h_proto);
    if(proto == 0x0800) printf("  (IPv4)");
    else if(proto == 0x0806) printf("  (ARP)");
    else if(proto == 0x86DD) printf("  (IPv6)");
    else printf("  (0x%04x)", proto);
    printf("\n");
}



// this function is a mess but it works and im not touching it
void process_ip_packet(unsigned char *buf, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buf;
    struct iphdr *ip = (struct iphdr *)(buf + sizeof(struct ethhdr));

    // i kept getting crashes here before i added this
    if(size < sizeof(struct ethhdr) + sizeof(struct iphdr)){
        printf("  [IP] truncated\n");
        return;
    }

    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    // inet_ntoa uses static buffer so cant do both in same printf
    // found this out the hard way lol
    char srcip[16], dstip[16];
    strcpy(srcip, inet_ntoa(src));
    strcpy(dstip, inet_ntoa(dst));

    printf("  [IP]  %s -> %s  ttl=%d", srcip, dstip, ip->ttl);

    int proto = ip->protocol;
    int iphdrlen = ip->ihl * 4;
    int header_offset = sizeof(struct ethhdr) + iphdrlen;

    // TCP
    if(proto == 6)
    {
        printf("  proto=TCP\n");
        tcp_count++;

        struct tcphdr *tcp = (struct tcphdr *)(buf + header_offset);
        printf("  [TCP] port %d -> %d", ntohs(tcp->source), ntohs(tcp->dest));

        // flags - this was annoying to figure out
        printf("  [");
        if(tcp->syn) printf("S");
        if(tcp->ack) printf("A");
        if(tcp->fin) printf("F");
        if(tcp->rst) printf("R");
        if(tcp->psh) printf("P");
        printf("]");
        printf("  seq=%u\n", ntohl(tcp->seq));
    }
    // UDP
    else if(proto == 17)
    {
        printf("  proto=UDP\n");
        udp_count++;

        struct udphdr* udp = (struct udphdr *)(buf + header_offset);
        printf("  [UDP] port %d -> %d  len=%d\n",
            ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len));
    }
    // ICMP
    else if(proto == 1)
    {
        printf("  proto=ICMP\n");
        icmp_cnt++;

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
        other++;
    }
}


// arp is simpler so i just did it inline
// offsets: hw type(2) proto(2) hwsize(1) protosize(1) opcode(2) = 8 bytes
// then sender hw(6) sender ip(4) target hw(6) target ip(4)
// so sender ip at 14, target ip at 24... wait no
// 8 + 6 = 14 for sender ip, 8 + 6 + 4 + 6 = 24 for target ip
// yeah that was right
void process_arp(unsigned char *buf, int len)
{
    unsigned char *arp = buf + 14;  // after eth header

    int opcode = (arp[6] << 8) + arp[7];

    printf("  [ARP] ");
    if(opcode == 1) printf("REQUEST");
    else if(opcode == 2) printf("REPLY  ");
    else printf("op=%d", opcode);

    // sender ip at offset 14 from arp start (6 bytes mac + 8 bytes before that)
    // wait no. hw type(2) + proto(2) + hwlen(1) + protolen(1) + op(2) + mac(6) = 14
    // hmm
    printf("  %d.%d.%d.%d", arp[14], arp[15], arp[16], arp[17]);
    printf(" -> ");
    printf("%d.%d.%d.%d", arp[24], arp[25], arp[26], arp[27]);

    // sender mac
    printf("  [%02x:%02x:%02x:%02x:%02x:%02x]",
        arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]);
    printf("\n");
}




int main(int argc, char** argv)
{
    unsigned char buffer[65536];
    int data_size;
    struct ethhdr *eth;
    unsigned short eth_type;

    signal(SIGINT, cleanup);

    printf("\n");
    printf("  ============================\n");
    printf("    pktsniff v0.1 \n");
    printf("  ============================\n\n");

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if(sock_raw < 0)
    {
        printf("  ERROR creating socket. u need root\n");
        printf("  try: sudo ./sniffer\n");
        return 1;
    }

    printf("  [*] sniffing... ctrl+c to stop\n\n");


    while(1)
    {
        data_size = recvfrom(sock_raw, buffer, 65536, 0, NULL, NULL);

        if(data_size < 0)
        {
            continue;
        }

        // was using this to debug something
        last_packet_size = data_size;

        pktcount++;

        printf("  ╔══════════════════════════════════════╗\n");
        printf("  ║  PACKET #%-6d   |  %5d bytes      ║\n", pktcount, data_size);
        printf("  ╚══════════════════════════════════════╝\n");

        print_ethernet(buffer, data_size);

        eth = (struct ethhdr *)buffer;
        eth_type = ntohs(eth->h_proto);

        if(eth_type == 0x0800)
        {
            process_ip_packet(buffer, data_size);
        }
        else if(eth_type == 0x0806)
        {
            process_arp(buffer, data_size);
            arp_cnt++;
        }
        else if(eth_type == 0x86DD)
        {
            // ipv6 is complicated, not dealing with it rn
            printf("  [IPv6] ...\n");
            ipv6cnt++;
        }
        else {
            other++;
        }

        if(show_hexdump){
            hexdump(buffer, data_size);
        }
        printf("\n");
    }

    close(sock_raw);
    return 0;
}