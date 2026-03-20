#include <stdio.h>
#include "util.h"

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