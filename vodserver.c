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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>


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
  struct in_addr sin_addr;	 /* IP address */
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
    VIEW,
    ADD,
    CONFIG,
    STATUS,
    NONE
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
    unsigned int rate ;
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


void *serve(void *arg);


/*
 * error - wrapper for perror
 */
void error(char *msg) {
  perror(msg);
  exit(1);
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



/*
 * parse - parse function takes care of the parsing of the requet sent by the
 * client. It returns a structure url_info, which contains different parts of
 * request. It returns a PARSE_ERROR if the request was malformed. For example:
 * input : char *buf - pointer to request string.
 *                  "GET http://www.example.com:8080/home.html HTTP/1.0"
 "http://localhost:8000/small.ogv"
 "http://localhost:8000/Users/Sanika/Desktop/cat.jpg"
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
        printf("500 Internal Server Error: Received a malformed request due to method/path/version\n");
        parse_url.result = PARSE_ERROR;
        return parse_url;
    }
    snprintf(parse_url.method , sizeof(method), "%s", method);
    printf("\n\n\nPATH: %s\n", path);
    if(sscanf(path, "%*c%[^/]%*c%[^?]%s", peer, pm, params) < 2 || strcmp(peer, "peer") !=0)
    {
      printf("\n\nNOT A VALID URI FOR PROJECT 2\n\n");
      parse_url.pm = NONE;
      return parse_url;
    }
    else
    {
      printf("\nPEER: %s\n METHOD: %s\n PARAMS: %s\n", peer, pm, params);
      if(strcmp(params, "") == 0)
      {
        //No parameters means this is a view or status request
        sscanf(pm, "%[^/]%s", temp, path);
        if(strcmp(temp, "view") == 0)
        {
          token = strtok(NULL, "");
          //VIEW REQUEST
          parse_url.pm = VIEW;
          snprintf(parse_url.path , sizeof(path), "%s", path);
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
    snprintf(parse_url.ext  , sizeof(ext), "%s", ext);
    parse_url.version = version;
    parse_url.result = PARSE_CORRECT;*/

   

    return parse_url;
}


    //Project 2 Parsing Change
    /*
    saved = path;
    sscanf(saved, "%[^&]&%s", path, saved);
    token = strtok(saved, "&");
    while (token) {
      sscanf(token, "%[^=]=%s", key, val);
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
  }*/
    //End Change


int main(int argc, char **argv) {
 int listenfd; /* listening socket */
    int portno; /* port to listen on */
    struct sockaddr_in serveraddr; /* server's addr */
    int optval; /* flag value for setsockopt */
    signal(SIGPIPE,SIG_IGN); //Sigpipe handling
    printf(get_rfc_time());
    /* check command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }
    portno = atoi(argv[1]);
    
    /* socket: create a socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0)
        error("ERROR opening socket");
    
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
    
    /* bind: associate the listening socket with a port */
    if (bind(listenfd, (struct sockaddr *) &serveraddr,
             sizeof(serveraddr)) < 0)
        error("ERROR on binding");
    
    /* listen: make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 1) < 0) /* allow 5 requests to queue up */
        error("ERROR on listen");
    
    /* main loop: wait for a connection request, echo input line,
     then close connection. */
    while (1) {
        pthread_t thread;
        /* Allocate space on the stack for client info */
        client_info *client = malloc(sizeof(*client));

        /* Initialize the length of the address */
        client->addrlen = sizeof(client->addr);

        /* accept: wait for a connection request */
        client->connfd = accept(listenfd, (struct sockaddr *) &client->addr, &client->addrlen);

        if (client->connfd < 0)
            error("ERROR on accept");
        
        /* Connection is established; serve client and create new thread */
        pthread_create(&thread, NULL, serve, client);// 
        
  }
}

void* serve(void* arg)
{
  client_info* client = arg;
  char buf[BUFSIZE]; /* message buffer */
  char response[MAXLINE];
  long size;
  struct hostent *hostp; /* client host info */
  char *hostaddrp; /* dotted decimal host addr string */
  long total_size;
  char *buf_file;
  int n, p; /* message byte size */
  char *token = NULL;
  char key[200];
  char val[200];
  char path[MAXLINE];
  int range_low = -1;
  int range_high = -1;
  char close_con = 0;
  char* content_type; // check initialization

  pthread_detach(pthread_self());
  /* gethostbyaddr: determine who sent the message */
  hostp = gethostbyaddr((const char *)&(client->addr).sin_addr.s_addr,
                              sizeof(&(client->addr).sin_addr.s_addr), AF_INET);
  if (hostp == NULL)
      error("ERROR on gethostbyaddr");
  hostaddrp = inet_ntoa((client->addr).sin_addr);
  if (hostaddrp == NULL)
      error("ERROR on inet_ntoa\n");
  printf("server established connection with %s (%s)\n",
  hostp->h_name, hostaddrp);

  /* read: read input string from the client */
  bzero(buf, BUFSIZE);

  n = read(client->connfd, buf, BUFSIZE);
  //Parse the request
  url_info sample = parse(buf);
  printf("%s parsed in to method: %s\npath: %s\n host: %s\n backend_port: %u\n rate: %u\n", 
    buf, sample.method, sample.path, sample.host, sample.back_port, sample.rate);
  sprintf(path, "./content%s", sample.path); // CHANGE PATH IF NEEDED in (.)
  printf("Parsing this: %s\nLooking for: %s\n", buf, path);
  // printf("%s\n""buf"); printf("%s\n", sample.path);
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
          close_con = 1;
      }
      token = strtok(NULL, "\r\n");
  }


  if (n < 0)
      error("ERROR reading from socket");
  printf("server received %d bytes: %s\n", n, buf);
  ftype *f_ext = file_types;
  while(f_ext->ext){
    if(strcmp(f_ext->ext,sample.ext)==0){
        content_type = f_ext->iana;
        break;
    }
    f_ext++;
  }

  if (strcmp(content_type, "x-icon")==0){
    close(client->connfd);
    return NULL;
  }
  
  /* Open the image on Desktop */
  FILE *file = fopen(path,"r");
  if(file) {
      if(range_low == -1 || range_high == -1)
      {
          //No Range Request
          fseek(file,0, SEEK_END);
          size = ftell(file);
          fseek(file,0,SEEK_SET);
          buf_file = malloc(size);
          fread(buf_file,1,size,file);
          sprintf(response, "HTTP/1.%c 200 OK\r\n", sample.version);
      }
      else
      {
          //Range Request
          fseek(file,0, SEEK_END);
          total_size = ftell(file);
          size = range_high - range_low;
          fseek(file,range_low, SEEK_SET);
          buf_file = malloc(size);
          int br = fread(buf_file,sizeof(unsigned char),size+1,file);
          sprintf(response, "HTTP/1.%c 206 Partial Content\r\n"
                  "Content-Range: bytes %d-%d/%lu\r\n", sample.version, 
                  range_low, range_high, total_size);
      }
      printf("Sending %ld bytes\n\n", size);
      sprintf(response,
              "%sContent-Type: %s\r\n"
              "Content-Length: %ld\r\n", response, content_type, size);
      
      //Get Last Modified Time
      char time_last[30];
      struct tm* ltm;
      struct stat attrib;
      stat(sample.path, &attrib);
      ltm = gmtime(&(attrib.st_mtime));
      sprintf(time_last, "%s, %d %s %d %d:%d:%d GMT", weekdays[ltm->tm_wday], ltm->tm_mday, months[ltm->tm_mon], 
        (ltm->tm_year + 1900), ltm->tm_hour, ltm->tm_min, ltm->tm_sec);

      if (close_con == 1){
          sprintf(response,"%sDate: %s\r\n"
                  "Last Modified: %s\r\n"
                  "Connection: Keep-Alive\r\n"
                  "Accept-Ranges: bytes\r\n"
                  "Connection: Closed\r\n\r\n", response, get_rfc_time(), time_last);
      }
      else {
            sprintf(response,"%sDate: %s\r\n"
                  "Last Modified: %s\r\n"
                  "Connection: Keep-Alive\r\n"
                  "Accept-Ranges: bytes\r\n\r\n", response, get_rfc_time(), time_last);

      }
      
      /* write: response to the client */


      n = write(client->connfd, response, strlen(response));
      if (n < 0)
           error("ERROR writing to socket");
      printf("%s", response);
      p = write(client->connfd, buf_file, size);
      if (p<0)
          error("ERROR writing file to socket");
      fclose(file);
  }
  else
  {
      sprintf(response, "HTTP/1.%c 404 Not Found\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: text/html\r\n"
        "Date: %s\r\n"
        "Connection: Closed\r\n\r\n", sample.version, strlen(error404), get_rfc_time());
      printf("%s\n", response);

      n = write(client->connfd, response, strlen(response));
      p = write(client->connfd, error404, strlen(error404));
      error("404 Bad request: File not Found!!");
  }
  close(client->connfd);
  return NULL;
}




