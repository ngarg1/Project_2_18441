#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void print_hex(const char *s)
{
  while(*s)
    printf("%02x", (unsigned int) *s++);
  printf("\n");
}


/*Our own custom UDP packet*/
typedef struct {
    char flags;                   //byte  0
    char pack;                    //byte  1
    uint16_t source_port;   //bytes 2  - 3
    uint16_t dest_port;     //bytes 4  - 5
    uint16_t length;        //bytes 6  - 7
    uint16_t syn;           //bytes 8  - 9
    uint16_t ack;           //bytes 10 - 11
    char* data;                   //bytes 12 - (12+length)
} packet;

char* package(packet* p)
{
    char* buf = malloc(sizeof(char)*p->length + 12);
    memcpy(buf, &(p->flags), 1);
    memcpy(buf+1, &(p->pack), 1);
    memcpy(buf+2, &(p->source_port), 2);
    memcpy(buf+4, &(p->dest_port), 2);
    memcpy(buf+6, &(p->length), 2);
    memcpy(buf+8, &(p->syn), 2);
    memcpy(buf+10, &(p->ack), 2);
    memcpy(buf+12, p->data, p->length);
    return buf;
}

packet* unwrap(char* buf)
{
    packet* p = (packet *)malloc(sizeof(packet));
    p->flags = buf[0];
    p->pack = 11;
    memcpy(&(p->source_port), buf+2, 2);
    memcpy(&(p->dest_port), buf+4, 2);
    memcpy(&(p->length), buf+6, 2);
    memcpy(&(p->syn), buf+8, 2);
    memcpy(&(p->ack), buf+10, 2);
    printf("\n1: %u 2: %u 3: %u\n", p->source_port, p->syn, p->ack);
    p->data = malloc(sizeof(char) * p->length);
    strncpy(p->data, buf+12, p->length);
    return p;
}

int main(int argc, char **argv)
{
    char* buf = "Hi everybody this is great ";
    char* pack;
    packet* p = (packet *)malloc(sizeof(packet));
    p->source_port = 1992;
    p->dest_port = 2008;
    p->length = strlen(buf);
    p->data = buf;
    p->ack = 34;
    p->syn = 49;
    p->flags = 8;
    p->pack = 11;
    pack = package(p);

    print_hex(pack);

    printf("PleasE: %s|%c", buf, buf[8]);
    packet* g = unwrap(pack);
    printf("\nPacket source port: %u\ndest: %u\nlength: %u\n", g->source_port, g->dest_port,
           g->length);
    printf("Flags: %u\nSyn: %u\nAck: %u\n", g->flags, g->syn,
           g->ack);
    printf("Data: %s\n", p->data);
}