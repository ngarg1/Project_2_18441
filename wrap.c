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

packet* unwrap(char* buf);
char* package(packet* p);
void addPeer(char *file, struct sockaddr_in, unsigned short int s_port);
void flow(char flow_ID, unsigned int s_addr, unsigned short int s_port, uint16_t base_syn, char *file);
packet* request_new_packet(char* path, char flowID, uint16_t source_port, uint16_t dest_port);
char getFlowID();
uint16_t getSequence();
void *serve(int connfd, fd_set* live_set);
char* get_rfc_time();


/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(1);
}

void printFlowTable()
{
    printf("~~~~~~~~~~~f l o w      t a b l e~~~~~~~~~~~~~~\n");
    for(int i = 0; i < flow_entries; i++)
    {
        printf("%d: %s | ", my_flow[i].pack, my_flow[i].filename);
    }
    printf("\n~~~~~~~~~~~e n d     t a b l e ~~~~~~~~~~~~~~\n");
}

void printPacket(packet* p)
{
    printf("------------------------Printing Packet-------------------------------------------\n");
    printf("flags: %u | flowID: %d | source_port: %u\n", p->flags, (int)p->pack, p->source_port);
    printf("dest_port: %u | length: %u\n", p->dest_port, p->length);
    printf("syn: %u | ack: %u\n", p->syn, p->ack);
    printf("window: %u | rtt: %u\n", p->window, p->rtt);
    printf("data: %s\n", p->data);
    printf("-----------------------------End Packet-------------------------------------------\n");

}

char getFlowID()
{
//Random Number Gen
    return (char)(rand()%255);
}

uint16_t getSequence()
{
//Random Number Gen
    return (uint16_t)(rand());
}

/* Addpeer: adds the peer address and port to the table */

void addPeer(char *file, struct sockaddr_in serveraddr, unsigned short int s_port){
    
    New_peer* np;
    printf("Adding new peer! %s %d %u\n", file, serveraddr.sin_addr.s_addr, s_port);
    //FIX THE GET ADDR INFO
    
    for(int i = 0; i < db_entries; i++){
        printf("Checking #%d %s\n", i, my_db[i].filename);
        np = &my_db[i];
        if (strcmp(np->filename, file) == 0) { //file found in database
            return;
        }
    }
    // if file not found, add to my_db (i value should be the one pointing to end of table from above
    np = malloc(sizeof(New_peer));
    np->filename = file;
    np->addr = serveraddr;
    np->port = s_port;
    my_db[db_entries] = *np;
    db_entries++;
    printf("added!\n");
    return;
}

void sendHeaders(char* file_size, char* filename, int clientfd){
    
    int n;
    char temp[MAXLINE];
    char extension[MAXLINE];
    char* content_type = NULL;
    char response[MAXLINE];
    
    if (sscanf(filename, "%[^.]%s", temp, extension) != 2) {
        printf("500 Internal Server Error:Received a malformed request due to extension \n");
        exit(1);
        return;
    }
    
    ftype *f_ext = file_types;
    while(f_ext->ext){
        if(strcmp(f_ext->ext,extension)==0){
            content_type = f_ext->iana;
            break;
        }
        f_ext++;
    }
    
    if (strcmp(content_type, "x-icon")==0){
        return;
    }
    
    sprintf(response, "HTTP/1.1 200 OK\r\n"
            "Content-Length: %s\r\n"
            "Content-Type: %s\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept-Ranges: bytes\r\n"
            "Date: %s\r\n\r\n", file_size, content_type, get_rfc_time());
    
    // Write response to fd
    
    n = write(clientfd, response, strlen(response));
    printf("The length of the headers: %lu written to clientfd: %d\n\n", strlen(response), clientfd);
    if (n < 0)
        error("ERROR writing to socket");
    printf("~~~~Sending Headers~~~~~\n%s\n\n", response);

    return;
    
}

int send_len(packet* p)
{
    return (16 + p->length) * sizeof(char);
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
        i++;
    }
    return res;
}

New_flow flow_add(char flow_ID, struct sockaddr_in addr, uint16_t syn, uint16_t ack, char* path, FILE* file, uint16_t size, int fd, uint16_t window)
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
    nf.window = window;

    my_flow[flow_entries] = nf;
    flow_entries++;
    return nf;
}

void getContent(char* path, int fd)
{
    struct sockaddr_in* provider = NULL;
    unsigned short port;
    char* buf;
    packet* req;

    //Look for who has the file in the lookup table
    for(int i = 0; i < db_entries; i++)
    {
        printf("Checking #%d %s\n", i, my_db[i].filename);
        if(strcmp(my_db[i].filename, path) == 0)
        {
            printf("Found the file!\n");
            provider = &(my_db[i].addr);
            port = my_db[i].port;
        }
    }
    if(provider == NULL)
    {
        printf("This file has not been added yet\n\n");
        return;
    }

    //create a new request packet
    req = request_new_packet(path, getFlowID(), back_port, port);
    buf = package(req);
    printf("Sending Request Packet: \n");
    printPacket(req);

    //Add to Flow Table
    flow_add(req->pack, *provider, req->syn, 0, path, NULL, 0, fd, req->window);

    //send the first request packet out
    //Timeout ask again sitch
    printf("Send Length: %d\n", send_len(req));
    if(sendto(back_fd, buf, send_len(req), 0, (struct sockaddr*)provider, sizeof(*provider)) < 0)
        printf("Error sending first request packet");
    return;
}


char* package(packet* p) // storing in packet in buf
{
    char* buf = malloc(sizeof(char)*p->length + sizeof(char)*16); 
    memcpy(buf, &(p->flags), 1);
    memcpy(buf+1, &(p->pack), 1);
    memcpy(buf+2, &(p->source_port), 2);
    memcpy(buf+4, &(p->dest_port), 2);
    memcpy(buf+6, &(p->length), 2);
    memcpy(buf+8, &(p->syn), 2);
    memcpy(buf+10, &(p->ack), 2);
    memcpy(buf+12, &(p->window), 2);
    memcpy(buf+14, &(p->rtt), 2);
    memcpy(buf+16, p->data, p->length);
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
    memcpy(&(p->window), buf+12, 2);
    memcpy(&(p->rtt), buf+14, 2);
    p->data = malloc(sizeof(char) * p->length);
    memcpy(p->data, buf+16, p->length);
    return p;
}


packet* request_new_packet(char* path, char flowID, uint16_t source_port, uint16_t dest_port)
{
    packet* p = (packet*)malloc(sizeof(packet));
    p->flags = 0x04;  //0x0100  Syn, no Ack, no Fin
    p->pack = flowID;
    p->source_port = source_port;
    p->dest_port = dest_port;
    p->length = strlen(path);
    p->syn = getSequence();
    p->ack = 67;    //NOT IMPORTANT
    p->data = path;
    p->window = window_g;
    return p;
}

static v;
packet* get_syn_ack(char flowID, uint16_t dest_port, uint16_t ack, char* data)
{

    clock_t t = clock();
    clock_t t1 =  t/CLOCKS_PER_SEC;
    v = t1;
    packet* p = (packet*)malloc(sizeof(packet));

    p->flags = 0x0c;   //0x1100 Syn, Ack, no Fin
    p->pack = flowID;
    p->source_port = back_port;
    p->dest_port = dest_port;
    p->ack = ack + 1;
    p->syn = getSequence();
    p->length = strlen(data);
    p->data = data;
    p->rtt = t; // base_time for rtt

    return p;
}

static rtt_val;

packet* get_ack(packet* p, New_flow* nf)
{

    static rtt;
    // clock_t t = clock();
    p->rtt = p->rtt/CLOCKS_PER_SEC;
    packet* g = (packet*)malloc(sizeof(packet));
    g->rtt = (p->rtt - v);

    rtt_val = g->rtt/1e3; // in seconds

    g->pack = p->pack;
    g->flags = 0x08;      //0x1000 Ack, No Syn, No Fin
    g->source_port = back_port;
    g->dest_port = p->source_port;
    g->length = 0;
    g->ack = nf->nss;
    nf->nss += 1;
    g->window = nf->window;
    g->syn = nf->naa;
    nf->naa += 1;
    g->data = NULL;
    if (rtt != 0)
        p->rtt = rtt;
    return g;
}




/* Time Declarations */
char* weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
char* months[] =  {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/*
 * get_rfc_time - returns a string with an RFC 1123 formatted string with the time in GMT
 * input: none
 * output: string - RFC formatted time
 */
char* get_rfc_time() {
    char time_string[30];
    time_t t;
    struct tm* tm;
    time(&t);
    tm = gmtime(&t);
    sprintf(time_string, "%s, %d %s %d %d:%d:%d GMT", weekdays[tm->tm_wday], tm->tm_mday, months[tm->tm_mon],
            (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
    return (char*)time_string;
}