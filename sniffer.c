// pktsniff

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <signal.h>

int pktcount = 0;
int sock_raw;

void cleanup(int sig){
    printf("\n\n stopped. got %d packets\n\n", pktcount);
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

    // handle last line padding
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




int main(int argc, char** argv)
{
    unsigned char buffer[65536];
    int data_size;

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
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , NULL, NULL);

        if(data_size < 0)
        {
            // recieve failed??
            continue;
        }

        pktcount++;

        printf("  ╔══════════════════════════════════════╗\n");
        printf("  ║  PACKET #%-6d   |  %5d bytes      ║\n", pktcount, data_size);
        printf("  ╚══════════════════════════════════════╝\n");

        hexdump(buffer, data_size);
        printf("\n");
    }

    close(sock_raw);
    return 0;
}