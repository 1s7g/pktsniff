#ifndef PARSE_H
#define PARSE_H

// returns protocol number for IP packets, -1 for non-ip
int print_ethernet(unsigned char* buf, int size);

void process_ip_packet(unsigned char *buf, int size, int *tcp_cnt, int *udp_cnt, int *icmp_cnt, int *other_cnt);

void process_arp(unsigned char *buf, int len);

// these are in parse.c but not really used externally anymore
// void print_tcp(...)
// void print_udp(...)
// whatever

#endif