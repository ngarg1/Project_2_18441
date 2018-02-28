/*
 * echoserver.c - A simple connection-based echo server
 * usage: echoserver <port>
 */

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

#if 0
/*
 * Structs exported from netinet/in.h (for easy reference)
 */

/* Internet address */
struct in_addr {
    unsigned int s_addr;
};

/* Internet style socket address */
struct sockaddr_in  {
    unsigned short int sin_family; /* Address family */
    unsigned short int sin_port;   /* Port number */
    struct in_addr sin_addr;     /* IP address */
    unsigned char sin_zero[...];   /* Pad to size of 'struct sockaddr' */
};

/*
 * Struct exported from netdb.h
 */

/* Domain name service (DNS) host entry */
struct hostent {
    char    *h_name;        /* official name of host */
    char    **h_aliases;    /* alias list */
    int     h_addrtype;     /* host address type */
    int     h_length;       /* length of address */
    char    **h_addr_list;  /* list of addresses */
}
#endif

const char* error404 = "<html><head><title>404 Error: Not Found</title></head><body>404 File Not Found</body></html>";

/* URI parsing results. */
typedef enum {
    PARSE_ERROR,
    PARSE_CORRECT
} parse_result;

/* Peer Functions*/
typedef enum {
    VIEW = 0,
    ADD = 1,
    CONFIG = 2,
    STATUS = 3,
    NONE = 4
} peer_method;

/* Client Info for Connection Thread*/
typedef struct {
    struct sockaddr_in addr;    // Socket address
    socklen_t addrlen;          // Socket address length
    int connfd;                 // Client connection file descriptor
    char host[HOSTLEN];         // Client host
    char serv[SERVLEN];         // Client service (port)
} client_info;

/* Parsed URI structure */
typedef struct {
    char method[MAXLINE];
    char path[MAXLINE];
    char version;
    char temp[MAXLINE];
    char ext[MAXLINE];
    char host[MAXLINE];
    unsigned int back_port;
    unsigned int rate;
    parse_result result;
    peer_method pm;
} url_info;

typedef struct {
    const char *ext;
    char *iana;
} ftype;

ftype file_types [] = {
    {".css", "text/css"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".gif", "image/gif"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".ico", "image/x-icon"},
    {".png", "image/png"},
    {".js", "application/javascript"},
    {".ogg", "video/ogg"},
    {".mp4", "video/mp4"},
    {".webm", "video/webm"},
    {".octet-stream","application/octet-stream"},
    {NULL, NULL},
};

/*Our own custom UDP packet*/
typedef struct {
    char flags;                   //byte  0     ASFX  (Ack, Syn, Fin, Unused)
    char pack;                    //byte  1 
    uint16_t source_port;   //bytes 2  - 3
    uint16_t dest_port;     //bytes 4  - 5
    uint16_t length;        //bytes 6  - 7
    uint16_t syn;           //bytes 8  - 9
    uint16_t ack;           //bytes 10 - 11
    char* data;                   //bytes 12 - (12+length)
} packet;

typedef struct{
    char *filename;
    struct sockaddr_in addr; //client socket address
    unsigned short port;
} New_peer;
//static New_peer new_peer;

/* peer database table*/
New_peer my_db[100];
static int db_entries = 0;

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


static int back_port;
static int back_fd;


packet* unwrap(char* buf);
char* package(packet* p);
void addPeer(char *file, struct sockaddr_in, unsigned short int s_port);
void flow(char flow_ID, unsigned int s_addr, unsigned short int s_port, uint16_t base_syn, char *file);
packet* request_new_packet(char* path, char flowID, uint16_t source_port, uint16_t dest_port);
char getFlowID();
uint16_t getSequence();
void *serve(int connfd, fd_set* live_set);

/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(1);
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
    char* content_type;
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
    
    sprintf(response, "HTTP/1.1 200 OK\r\n",
            "Content-Type: %s\r\n"
            "Content-Length: %ld\r\n", content_type, file_size);
    
    // Write response to fd
    
    n = write(clientfd, response, strlen(response));
    if (n < 0)
        error("ERROR writing to socket");
    printf("%s", response);
    return;
    
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

void getContent(char* path, int fd)
{
    struct sockaddr* provider;
    unsigned short port;
    char* buf;
    packet* req;

    //Look for who has the file in the lookup table
    for(int i = 0; i < db_entries; i++)
    {
        if(strcmp(my_db[i].filename, path) == 0)
        {
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

    //Add to Flow Table
    flow_add(req->pack, *provider, req->syn, 0, path, NULL, 0, fd);

    //send the first request packet out
    //Timeout ask again sitch
    if(sendto(back_fd, buf, strlen(buf), 0, provider, sizeof(*provider)) < 0)
        printf("Error sending first request packet");
    return;
}

/*
void flow(char flow_ID, unsigned int s_addr, unsigned short int s_port, uint16_t base_syn, char *file) {
    New_flow* nf;
    for(int i = 0; i < flow_entries; i++)
    {
        nf = &my_flow[i];
        if(nf->pack == flow_ID) // Flow exists
        {
            printf("\n We tried to add an existing flow twice! \n");
            return;//continue with the flow
        }
    }
    // flow doesn't exist, add to the flow table and send
    nf = malloc(sizeof(New_flow));
    nf->pack = flow_ID;
    nf->addr.sin_family = AF_INET;
    nf->addr.sin_addr.s_addr = s_addr;
    nf->addr.sin_port = s_port;
    nf->base_syn = base_syn;
    memcpy(nf->filename, file, strlen(file));
    my_flow[flow_entries] = *nf;
    flow_entries++;

    // added to the flow table
    return; //continue with UDP transfer  
}*/

char* package(packet* p) // storing in packet in buf
{
    char* buf = malloc(sizeof(char)*p->length + 12); // ??
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
    printf("\n1: %u 2: %u 3: %u\n", p->source_port, p->syn, p->ack);
    p->data = malloc(sizeof(char) * p->length);
    strncpy(p->data, buf+12, p->length);
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
    return p;
}


packet* get_syn_ack(char flowID, uint16_t dest_port, uint16_t ack, char* data)
{
    packet* p = (packet*)malloc(sizeof(packet));

    p->flags = 0x0c;   //0x1100 Syn, Ack, no Fin
    p->pack = flowID;
    p->source_port = back_port;
    p->dest_port = dest_port;
    p->ack = ack + 1;
    p->syn = getSequence();
    p->length = strlen(data);
    p->data = malloc(sizeof(char) * p->length);

    return p;
}

packet* get_ack(packet* p)
{
    packet* g = (packet*)malloc(sizeof(packet));

    g->pack = p->pack;
    g->flags = 0x08;      //0x1000 Ack, No Syn, No Fin
    g->source_port = back_port;
    g->dest_port = p->source_port;
    g->length = 0;
    g->ack = p->syn + 1;
    g->syn = p->ack;
    g->data = NULL;

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
    return time_string;
}

static int bps = 0;

/*
 * parse - parse function takes care of the parsing of the requet sent by the
 * client. It returns a structure url_info, which contains different parts of
 * request. It returns a PARSE_ERROR if the request was malformed. For example:
 * input : char *buf - pointer to request string.
 *                  "GET http://www.example.com:8080/home.html HTTP/1.0"
 "http://localhost:8000/small.ogv"
 "http://localhost:8000/Users/Sanika/Desktop/cat.jpg"
 GET /peer/add/?path=video.ogg &host=10.0.0.2&port=81
 
 http://localhost:8345/peer/add?path=/Users/Sanika/Desktop/Documents/Project_2_18441/content/hi.jpg&host=pi.ece.cmu.edu&port=8346
 
 "GET /small.ogv HTTP/1.1\r\n\r\n"
 "GET /Users/Sanika/Desktop/cat.jpg HTTP/1.1"
 * output : url_info parse_url- a structure containing different parsed values.
 *                  .method - "GET"
 *                  .url - "www.example.com:8080/home.html"
 *                  .host - "www.example.com"
 *                  .path - "Users/Sanika/Desktop/cat.jpg"
 *                  .port - "8080"
 *                  .version - 0
 *                  .extension - jpg/txt etc.
 *                  .parse_result - PARSE_CORRECT(PARSE_ERROR if Error)
 */

url_info parse(char *buf){
    char method[MAXLINE];
    char path[MAXLINE];
    char version;
    char temp[MAXLINE];
    char ext[MAXLINE];
    char params[MAXLINE];
    char pm[MAXLINE];
    char* token;
    char key[200];
    char val[200];
    char peer[MAXLINE];
    url_info parse_url;
    
    /* sscanf must parse exactly 3 things for request line to be well-formed */
    /* version must be either HTTP/1.0 or HTTP/1.1 */
    if (sscanf(buf, "%s %s HTTP/1.%c", method, path, &version) != 3
        || (version != '0' && version != '1')) {
        printf("\n\nBUF: %s\n", buf);
        printf("500 Internal Server Error: Received a malformed request due to method/path/version\n");
        parse_url.result = PARSE_ERROR;
        return parse_url;
    }
    snprintf(parse_url.method , sizeof(method), "%s", method);
    printf("\n\n\nPATH with everything: %s\n", path);
    if(sscanf(path, "%*c%[^/]%*c%[^?]%s", peer, pm, params) < 2 || strcmp(peer, "peer") !=0)
    {
        printf("\n\nNOT A VALID URI FOR PROJECT 2\n\n");
        parse_url.pm = NONE;
        return parse_url;
    }
    else
    {
        printf("\nPEER: %s\n METHOD: %s\n PARAMS: %s\n", peer, pm, params);
        if(pm[0] == 'v')
        {
            //No parameters means this is a view or status request
            sscanf(pm, "%[^/]%s", temp, path);
            if(strcmp(temp, "view") == 0)
            {
                token = strtok(NULL, "");
                //VIEW REQUEST
                parse_url.pm = VIEW;
                snprintf(parse_url.path , sizeof(path), "%s", path);
                printf("PATH: %s\n\n", parse_url.path);
                if (sscanf(path, "%[^.]%s", temp, ext) != 2)
                {
                    printf("500 Internal Server Error:Received a malformed request due to extension \n");
                    parse_url.result = PARSE_ERROR;
                    return parse_url;
                }
                snprintf(parse_url.ext  , sizeof(ext), "%s", ext);
                //printf("\n\nVIEW\npath: %s\next: %s\n", parse_url.path, ext);
            }
        }
        else
        {
            //There are parameters so this an add or config
            if(strcmp(pm, "add") == 0)
            {
                //ADD action
                parse_url.pm = ADD;
            }
            else if(strcmp(pm, "config") == 0)
            {
                //CONFIG action
                parse_url.pm = CONFIG;
            }
            
            //Parse the parameters
            token = strtok(params, "&");
            token = token + 1;
            while (token)
            {
                sscanf(token, "%[^=]=%s", key, val);
                if(strcmp(key, "path") == 0)
                {
                    snprintf(parse_url.path , sizeof(val), "%s", val);
                    if (sscanf(parse_url.path, "%[^.]%s", temp, ext) != 2)
                    {
                        printf("500 Internal Server Error: File Name incorrectly formatted \n");
                    }
                    snprintf(parse_url.ext , sizeof(ext), "%s", ext);
                }
                if(strcmp(key, "host") == 0)
                {
                    snprintf(parse_url.host , sizeof(val), "%s", val);
                }
                if(strcmp(key, "port") == 0)
                {
                    parse_url.back_port = (unsigned int)atoi(val);
                }
                if(strcmp(key, "rate") == 0)
                {
                    parse_url.rate = (unsigned int)atoi(val);
                }
                token = strtok(NULL, "&");
            }
        }
        
        
    }
    
    // printf("path: %s\n", path);
    // printf("Parsing this: %s\n", buf);
    
    /*if (sscanf(path, "%[^.]%s", temp, ext) != 2) {
     printf("500 Internal Server Error:Received a malformed request due to extension \n");
     parse_url.result = PARSE_ERROR;
     return parse_url;
     }
     snprintf(parse_url.method , sizeof(method), "%s", method);
     snprintf(parse_url.path   , sizeof(path), "%s", path);
     snprintf(parse_url.ext  , sizeof(ext), "%s", ext);*/
     parse_url.version = version;
     parse_url.result = PARSE_CORRECT;
    return parse_url;
}




void backend(int on_fd)
{
    char buf[MAXLINE];
    char data[MAXLINE];
    struct sockaddr sender;
    long size;
    socklen_t sender_len;
    packet* p;
    New_flow* nf;
    if(recvfrom(on_fd, buf, MAXLINE, 0, &sender, &sender_len) < 0)
    {
        printf("Error receiving packet on Backend Connection\n\n");
        return;
    }
    p = unwrap(buf);
    if(p->flags == 0x04)
    {
        //No Ack, but Syn

        //Receiving a new connection
        if(flow_look(p->pack) != NULL)
        {
            printf("This flow id is already in use!");
            return;
        }


        //get file length
        FILE* file = fopen(p->data,"r");
        if(file == NULL)
        {
            printf("Could not find the desired file");
            return;
        }
        fseek(file,0, SEEK_END);
        size = ftell(file);
        sprintf(data, "%ld", size);
        
        //Get SYN ACK packet
        packet* g = get_syn_ack(p->pack, p->source_port, (p->syn), data);

        //add to Flow Table
        flow_add(p->pack, sender, g->syn, g->ack, p->data, file, size, -1);
        
        //send syn ack
        strcpy(buf, package(g));
        if(sendto(on_fd, buf, strlen(buf), 0, &sender, sizeof(sender)) < 0)
        {
            printf("Error while trying to send a SYN ACK");
            return;
        }
    }
    else if(p->flags == 0x0c)
    {
        //Receiving a SYN ACK
        //find the flow
        nf = flow_look(p->pack);

        if(nf == NULL)
        {
            printf("Could not find the flow that a SYN ACK responds to\n");
            return;
        }

        //send headers
        sendHeaders(p->data, nf->filename, nf->client_fd);

        //Check to see that the seq number is good
        if((p->ack - nf->syn) != 1)
        {
            printf("Out of sync!! \n");

        }

        //Send ack
        packet* g = get_ack(p);


        //send ack
        strcpy(buf, package(g));
        if(sendto(on_fd, buf, strlen(buf), 0, &sender, sizeof(sender)) < 0)
        {
            printf("Error while trying to send a SYN ACK");
            return;
        }

        //update flow table
        nf->syn = g->syn;
        nf->ack = g->ack;
        nf->file_size = atoi(p->data);

        free(p);
    }
    else if(p->flags == 0x08)
    {
        //Normal ACK Case

        //Look Up the Flow
        nf = flow_look(p->pack);
        if(nf == NULL)
        {
            printf("Could not find the flow that the ACK responds to\n");
            return;
        }


        if(nf->client_fd == -1)
        {
            //Sender of Data
            //make sure in sync
            if(p->ack - nf->syn != 1)
            {
                printf("Out of sync!!");
                //resend last packet
            }
            //Find specified block of data
            int index = p->syn - nf->base_syn - 1;
            fseek(nf->file, 1400 * index, SEEK_SET);

            //get ack skeleton
            packet* g = get_ack(p);

            //fill data
            g->data = malloc(sizeof(char)*1400);
            int br = fread(g->data, 1, 1400, nf->file);
            g->length = br;

            //Check if you finished the file
            if(br < 1400)
            {
                g->flags = (g->flags | 0x02);  //flags = flags | 0x0010  set FIN flag
            }

            //send ack
            strcpy(buf, package(g));
            if(sendto(on_fd, buf, strlen(buf), 0, &sender, sizeof(sender)) < 0)
            {
                printf("Error while trying to send a SYN ACK");
                return;
            }

            //update flow table
            nf->syn = g->syn;
            nf->ack = g->ack;

            free(p);
        }
        else
        {
            //CHANGES AFTER SANI STARTED LOOKING

            //Receiver of Data
            //make sure in sync
            if(p->ack - nf->syn != 1)
            {
                printf("Out of sync!!");
                //resend last packet
            }
            //send data
            if(write(nf->client_fd, p->data, p->length) < 0)
            {
                printf("Failed writing to client socket with file data\n");
            }

            //Send ack
            packet* g = get_ack(p);

            strcpy(buf, package(g));
            if(sendto(on_fd, buf, strlen(buf), 0, &sender, sizeof(sender)) < 0)
            {
                printf("Error while trying to send a SYN ACK");
                return;
            }

            //update flow table
            nf->syn = g->syn;
            nf->ack = g->ack;
        }
    }
    else if(p->flags == 0x0a)
    {
        //FIN ACK
        //look up flow
        nf = flow_look(p->pack);
        if(nf == NULL)
        {
            printf("Could not find the flow that the ACK responds to\n");
            return;
        }

        //see if in sync
        if(p->ack - nf->syn != 1)
        {
            printf("Out of sync!!");
            //resend last packet
        }

        
        if(nf->client_fd == -1)
        {
            //There should be last bit of data to relay
            
            //send data
            if(write(nf->client_fd, p->data, p->length) < 0)
            {
                printf("Failed writing to client socket with file data\n");
            }
            packet* g = get_ack(p);
            g->flags = g->flags | 0x02; //Set the fin flag

            //Send the fin ack
            strcpy(buf, package(g));
            if(sendto(on_fd, buf, strlen(buf), 0, &sender, sizeof(sender)) < 0)
            {
                printf("Error while trying to send a SYN ACK");
                return;
            }
        }
        remove_flow(nf->pack);
        free(nf);
    }
}



int main(int argc, char **argv) {
    int listenfd; /* listening socket for http */
    int portno; /* port to listen on */
    int on_fd, left;
    int result;
    int new_fd = 0;
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in backaddr;
    int optval; /* flag value for setsockopt */
    fd_set curr_set, live_set; /* Set of active fd's */ //????
    
    signal(SIGPIPE,SIG_IGN); //Sigpipe handling
    
    /* check command line args */
    if (argc != 3) {
        fprintf(stderr, "usage: %s <port> <backend_port>\n", argv[0]);
        exit(1);
    }
    portno = atoi(argv[1]);
    back_port = atoi(argv[2]);
    
    srand(time(NULL)); //Initialize random number generator

    /* socket: create a socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    back_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd < 0)
        error("ERROR opening socket");
    if (back_fd < 0)
        error("ERROR opening backend socket");
    
    /* setsockopt: Handy debugging trick that lets
     * us rerun the server immediately after we kill it;
     * otherwise we have to wait about 20 secs.
     * Eliminates "ERROR on binding: Address already in use" error.
     */
    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval , sizeof(int));
    
    /* build the server's internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET; /* we are using the Internet */
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); /* accept reqs to any IP addr */
    serveraddr.sin_port = htons((unsigned short)portno); /* port to listen on */
    
    setsockopt(back_fd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval , sizeof(int));
    
    /* build the server's internet address */
    bzero((char *) &backaddr, sizeof(backaddr));
    backaddr.sin_family = AF_INET; /* we are using the Internet */
    backaddr.sin_addr.s_addr = htonl(INADDR_ANY); /* accept reqs to any IP addr */
    backaddr.sin_port = htons((unsigned short)back_port); /* port to listen on */
    
    /* bind: associate the listening socket with a port */
    if (bind(listenfd, (struct sockaddr *) &serveraddr,
             sizeof(serveraddr)) < 0)
        error("ERROR on binding");
    
    if (bind(back_fd, (struct sockaddr *) &backaddr,
             sizeof(backaddr)) < 0)
        error("ERROR on binding backend");
    
    /* listen: make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */
        error("ERROR on listen");
    
    FD_ZERO(&curr_set);
    FD_ZERO(&live_set);
    FD_SET(listenfd, &live_set);
    FD_SET(back_fd, &live_set);//add live_set to listening and backend fd??
    
    /* main loop */
    while (1) {
        curr_set = live_set;
        // curr_set always overwritten from the beginning???\
        // where do we set FD_SETSIZE?
        result = select(FD_SETSIZE, &curr_set, NULL, NULL, NULL);
        
        if(result < 0)
            error("Select failed!");
        for(on_fd = 0; on_fd < FD_SETSIZE; ++on_fd)
        {
            if (FD_ISSET(on_fd, &curr_set))
            {
                printf("ON_FD is %d \n", on_fd);
                if(on_fd == listenfd)
                {
                    //Listening Port Got a Request
                    
                    while(new_fd != -1)
                    {
                        new_fd = accept(listenfd, NULL, NULL);
                        if(new_fd < 0)
                        {
                            printf("ACCEPT Failed with error fd: %d\n", new_fd);
                        }
                        else{
                            printf("  New incoming connection - %d\n", new_fd);
                            FD_SET(new_fd, &live_set);
                            break;
                        }
                    }
                }
                else if(on_fd == back_fd)
                {
                    //BACKEND PORT WANTS SOME SERVICE
                    //recvfrom/
                    backend(on_fd);
                }
                else
                {
                    //SERVICE -- Get Request -- Could be ADD, VIEW, CONFIG, OR OTHER
                    printf("  Descriptor %d is readable\n", on_fd);
                    serve(on_fd, &live_set);
                }
            }
        }
    }
}


void* serve(int connfd, fd_set* live_set)
{
    char buf[BUFSIZE]; /* message buffer */
    int n; /* message byte size */
    char *token = NULL;
    char key[200];
    char val[200];
    char response[MAXLINE];
    int range_low = -1;
    int range_high = -1;
    char* content_type = NULL; 

    struct sockaddr_in serveraddr;
    struct hostent *server;
    int sockfd;

    
    /* read: read input string from the client */
    bzero(buf, BUFSIZE);
    
    n = read(connfd, buf, BUFSIZE);
    if (n < 0)
        error("ERROR reading from socket");
    //Parse the request
    url_info* sample = (url_info*)malloc(sizeof(url_info));
    bzero(sample, sizeof(url_info));
    *sample = parse(buf);

    if(sample->result == 0)
    {
        FD_CLR(connfd, live_set);
        close(connfd);
        return NULL;
    }
    
    printf("%s parsed in to method: %s\npath: %s\n host: %s\n backend_port: %u\n rate: %u\nextension: %s\n",
           buf, sample->method, sample->path, sample->host, sample->back_port, sample->rate, sample->ext);   
    
    //Parse the headers
    token = strtok(buf, "\r\n");
    token = strtok(NULL, "\r\n");
    while (token) {

        sscanf(token, "%[^:]: %s", key, val);
        if(strcmp(key, "Range") == 0)
        {
            sscanf(val, "%*[^=]=%d-%d", &range_low, &range_high);
        }
        if(strcmp(key, "Connection") == 0 && strcmp(val, "close") == 0)
        {
            FD_CLR(connfd, live_set);
            close(connfd);
        }
        token = strtok(NULL, "\r\n");
    }


    ftype *f_ext = file_types;
    while(f_ext->ext){
        if(strcmp(f_ext->ext,sample->ext)==0)
        {
            content_type = f_ext->iana;
            break;
        }
        f_ext++;
    }
    if (strcmp(content_type, "x-icon")==0)
    {
        return NULL;
    }
    printf("peer method: %d\n", sample->pm);
    
    switch(sample->pm)
    {
        case 1:   //ADD
            printf("HTTP Server has seen a peer ADD request\n");
            
            /* socket: create the socket */
            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd < 0)
                error("ERROR opening socket");
            
            /* gethostbyname: get the server's DNS entry */
            server = gethostbyname((const char *)sample->host);
            
            if (server == NULL) {
                fprintf(stderr,"ERROR, no such host as %s\n", sample->host);
                exit(1);
            }

            /* build the server's Internet address */
            bzero((char *) &serveraddr, sizeof(serveraddr));
            serveraddr.sin_family = AF_INET;
            bcopy((char *)server->h_addr,
                  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
            serveraddr.sin_port = htons(sample->back_port);
            
            
            addPeer(sample->path, serveraddr, (unsigned short int)sample->back_port);
            if(sample->rate != 0)
            {
                bps = sample->rate;
            }
            break;

        case 0:   //VIEW
            printf("HTTP Server has seen a peer VIEW request\n");
            getContent(sample->path, connfd);
            break;

        case 2:   //CONFIG
            printf("HTTP Server has seen a peer CONFIG request\n");
            bps = sample->rate;
            break;

        default:  //
            printf("HTTP Server has seen an unsupported request\n");
            break;
    }

    
    return NULL;
}




