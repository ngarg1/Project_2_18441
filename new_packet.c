#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>

#define BUFSIZE 1024
#define MAXLINE 8192
#define SERVLEN 100
#define HOSTLEN 256



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

void print_hex(const char *s)
{
  while(*s)
    printf("%02x", (unsigned int) *s++);
  printf("\n");
}


/* newflow struct for flow table */
typedef struct{
    char pack; // ID for the flow
    struct sockaddr addr;
    socklen_t addrlen;
    uint16_t base_syn;
    uint16_t syn; //init
    uint16_t ack;
    char filename[MAXLINE];
    FILE* file;
    long file_size;
    int client_fd;
} New_flow;
//static New_flow new_flow;

/* flow database */
New_flow my_flow[25];
static int flow_entries = 0;

void printFlowTable()
{
    printf("~~~~~~~~~~~f l o w      t a b l e~~~~~~~~~~~~~~\n");
    for(int i = 0; i < flow_entries; i++)
    {
        printf("%d: %s |", my_flow[i].pack, my_flow[i].filename);
    }
    printf("\n~~~~~~~~~~~e n d     t a b l e \n~~~~~~~~~~~~~~\n");
}

void printPacket(packet* p)
{
    printf("------------------------Printing Packet-------------------------------------------\n");
    printf("flags: %u | flowID: %d | source_port: %u\n", p->flags, (int)p->pack, p->source_port);
    printf("dest_port: %u | length: %u\n", p->dest_port, p->length);
    printf("syn: %u | ack: %u\n", p->syn, p->ack);
    printf("data: %s\n", p->data);
    printf("-----------------------------End Packet-------------------------------------------\n");

}

New_flow* flow_look(char flow_ID)
{
    New_flow* nf;
    for(int i = 0; i < flow_entries; i++)
    {
        nf = &my_flow[i];
        if(nf->pack == flow_ID) // Flow exists
        {
            return nf;
        }
    }
    return NULL;
}

int remove_flow(char flow_ID)
{
    int res = 0;
    int i;
    New_flow* nf;
    for(i = 0; i < flow_entries; i++)
    {
        nf = &my_flow[i];
        if(nf->pack == flow_ID) // Flow exists
        {
            res = 1;
            flow_entries--;
            break;
        }
    }
    while(i < flow_entries)
    {
        my_flow[i] = my_flow[i+1];
    }
    free(nf);
    return res;
}

New_flow flow_add(char flow_ID, struct sockaddr addr, uint16_t syn, uint16_t ack, char* path, FILE* file, uint16_t size, int fd)
{
    New_flow nf;
    nf.pack = flow_ID;
    nf.addr = addr;
    nf.base_syn = syn;
    nf.syn = syn;
    nf.ack = ack;
    strcpy(nf.filename, path);
    nf.file = file;
    nf.file_size = size;
    nf.client_fd = fd;

    my_flow[flow_entries] = nf;
    flow_entries++;
    return nf;
}


packet* request_new_packet(char* path, char flowID, uint16_t source_port, uint16_t dest_port)
{
    packet* p = (packet*)malloc(sizeof(packet));
    p->flags = 0x04;  //0x0100  Syn, no Ack, no Fin
    p->pack = flowID;
    p->source_port = source_port;
    p->dest_port = dest_port;
    p->length = strlen(path);
    p->syn = 71;
    p->ack = 67;    //NOT IMPORTANT
    p->data = path;
    return p;
}

char* package(packet* p) // storing in packet in buf
{
    char* buf = malloc(sizeof(char)*p->length + sizeof(char)*12); // ??
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
    p->pack = buf[1]; 
    memcpy(&(p->source_port), buf+2, 2);
    memcpy(&(p->dest_port), buf+4, 2);
    memcpy(&(p->length), buf+6, 2);
    memcpy(&(p->syn), buf+8, 2);
    memcpy(&(p->ack), buf+10, 2);
    p->data = malloc(sizeof(char) * p->length);
    strncpy(p->data, buf+12, p->length);
    return p;
}

int main(int argc, char **argv)
{
    char* buf = "Hi everybody this is great ";
    char* pack;
    char* path = "content/hb.mp4";
    packet* p = request_new_packet(path, 5, 4045, 4045);
    /*(packet *)malloc(sizeof(packet));
    p->source_port = 1992;
    p->dest_port = 2008;
    p->length = strlen(buf);
    p->data = buf;
    p->ack = 34;
    p->syn = 49;
    p->flags = 8;
    p->pack = 11;*/
    printPacket(p);
    pack = package(p);

    print_hex(pack);

    printf("PleasE: %s|%c\n\n", buf, buf[8]);
    packet* g = unwrap(pack);
    printPacket(g);

    printFlowTable();
    struct sockaddr s;
    flow_add(1, s, 1, 1, "content/hb.mp4", NULL, 400, 1);
    printFlowTable();
}