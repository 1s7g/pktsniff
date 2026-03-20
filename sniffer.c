// pktsniff

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <signal.h>
#include "parse.h"
#include "util.h"

int pktcount = 0;
int sock_raw;
int tcp_count, udp_count, icmp_cnt = 0;
int arp_cnt = 0;
int ipv6cnt;
int other = 0;

// options
int show_hex = 1;
int filter_tcp = 0;
int filter_udp = 0;
int filter_icmp = 0;
int filter_arp = 0;
int filter_port = -1;

void print_usage()
{
    printf("\n");
    printf("  usage: sudo ./sniffer [options]\n");
    printf("\n");
    printf("  options:\n");
    printf("    -t, --tcp      only show tcp\n");
    printf("    -u, --udp      only show udp\n");
    printf("    -i, --icmp     only show icmp\n");
    printf("    -a, --arp      only show arp\n");
    printf("    -p, --port N   filter by port\n");
    printf("    -x, --no-hex   hide hex dump\n");
    printf("    -h, --help     this\n");
    printf("\n");
}


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


int main(int argc, char** argv)
{
    unsigned char buffer[65536];
    int data_size;
    int ethtype;
    struct iphdr *ip;
    int skip;

    // arg parsing
    for(int i = 1; i < argc; i++)
    {
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage();
            return 0;
        }
        else if(strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0)
        {
            filter_tcp = 1;
        }
        else if(strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0)
        {
            filter_udp = 1;
        }
        else if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--icmp") == 0)
        {
            filter_icmp = 1;
        }
        else if(strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--arp") == 0)
        {
            filter_arp = 1;
        }
        else if(strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--no-hex") == 0)
        {
            show_hex = 0;
        }
        else if(strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0)
        {
            if(i + 1 >= argc){
                printf("  -p needs a port number\n");
                return 1;
            }
            i++;
            filter_port = atoi(argv[i]);
            if(filter_port <= 0 || filter_port > 65535){
                printf("  invalid port: %s\n", argv[i]);
                return 1;
            }
        }
        else
        {
            printf("  unknown option: %s\n", argv[i]);
            print_usage();
            return 1;
        }
    }


    signal(SIGINT, cleanup);

    printf("\n");
    printf("  ============================\n");
    printf("    pktsniff v0.2 \n");
    printf("  ============================\n\n");

    if(filter_tcp || filter_udp || filter_icmp || filter_arp || filter_port != -1)
    {
        printf("  [*] filters: ");
        if(filter_tcp) printf("TCP ");
        if(filter_udp) printf("UDP ");
        if(filter_icmp) printf("ICMP ");
        if(filter_arp) printf("ARP ");
        if(filter_port != -1) printf("port=%d ", filter_port);
        printf("\n");
    }
    if(!show_hex) printf("  [*] hex dump disabled\n");

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

        if(data_size < 0) continue;

        struct ethhdr *e = (struct ethhdr *)buffer;
        ethtype = ntohs(e->h_proto);
        
        skip = 0;

        // filtering logic (this got messy)
        if(filter_tcp || filter_udp || filter_icmp || filter_arp)
        {
            if(ethtype == 0x0806)
            {
                if(!filter_arp) skip = 1;
            }
            else if(ethtype == 0x0800)
            {
                ip = (struct iphdr*)(buffer + 14);
                if(ip->protocol == 6 && !filter_tcp) skip = 1;
                if(ip->protocol == 17 && !filter_udp) skip = 1;
                if(ip->protocol == 1 && !filter_icmp) skip = 1;
                // what about other protocols? uhh
                if(ip->protocol != 6 && ip->protocol != 17 && ip->protocol != 1)
                    skip = 1;
            }
            else
            {
                skip = 1;  // ipv6 etc, just skip when filtering
            }
        }

        // port filter
        if(filter_port != -1 && !skip)
        {
            if(ethtype != 0x0800){
                skip = 1;
            } else {
                ip = (struct iphdr*)(buffer + 14);
                if(ip->protocol == 6 || ip->protocol == 17)
                {
                    int hlen = ip->ihl * 4;
                    unsigned char *l4 = buffer + 14 + hlen;
                    int sp = (l4[0] << 8) + l4[1];
                    int dp = (l4[2] << 8) + l4[3];
                    if(sp != filter_port && dp != filter_port)
                        skip = 1;
                }
                else
                {
                    skip = 1;  // not tcp/udp, no ports
                }
            }
        }

        if(skip) continue;

        pktcount++;

        printf("  ╔══════════════════════════════════════╗\n");
        printf("  ║  PACKET #%-6d   |  %5d bytes      ║\n", pktcount, data_size);
        printf("  ╚══════════════════════════════════════╝\n");

        ethtype = print_ethernet(buffer, data_size);

        if(ethtype == 0x0800)
        {
            process_ip_packet(buffer, data_size, &tcp_count, &udp_count, &icmp_cnt, &other);
        }
        else if(ethtype == 0x0806)
        {
            process_arp(buffer, data_size);
            arp_cnt++;
        }
        else if(ethtype == 0x86DD)
        {
            printf("  [IPv6] ...\n");
            ipv6cnt++;
        }
        else {
            other++;
        }

        if(show_hex){
            hexdump(buffer, data_size);
        }
        printf("\n");
    }

    close(sock_raw);
    return 0;
}