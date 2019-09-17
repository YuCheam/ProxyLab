#include <stdio.h>
#include "csapp.h"

#define MAX_OBJECT_SIZE 7204056
/* You won't lose style points for including this long line in your code */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";

/* Cache Variables */
typedef struct cache_entry{
  char * url;
  char *response_header;
  char file_buf[MAX_OBJECT_SIZE];
  int content_length;
} cache_entry;

cache_entry *entry;

typedef struct rangeNode {
  int type;
  int first;
  int second;
} rangeNode;

/* Function Declarations */
void doit(int fd);
int read_requesthdrs(rio_t *rp, char buf[], char *hostname, char *path, 
   char *proxy_request, rangeNode *nodePtr);
void process_range(char *buf, rangeNode *nodePtr);
void parse_uri(char *uri, char *hostname, char *path, char *port);
int send_request(int clientfd, char* proxy_request, char *port, char *hostname,
    char *url, rangeNode *nodePtr);
int valid_range(rangeNode *nodePtr, int c_length, int valid); 
void get_url(char *uri, char *url);
void create_entry(int content_length, char *url, char *save_header,
    char *save_data); 
void edit_response(char *save_header, char *range_header, rangeNode *nodePtr); 

int main(int argc, char **argv)
{
  int listenfd, conn_fd;
  int error;
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
  char client_hostname[MAXLINE], client_port[MAXLINE];
  
  /* Initialize Entry */
  entry = (cache_entry*)malloc(sizeof(*entry));
  entry->url = NULL;
  entry->response_header = NULL;
  strcpy(entry->file_buf, "\0");
  entry->content_length = 0;

  printf("%s", user_agent_hdr);
  
  /* Check command line arguement */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  Signal(SIGPIPE, SIG_IGN);

  listenfd = Open_listenfd(argv[1]);
  while (1) {
    clientlen = sizeof(clientaddr);
    
    if ((conn_fd = accept(listenfd, (SA *) &clientaddr, &clientlen)) < 0) {
      fprintf(stderr, "System call accept encountered error: %s\n", 
          strerror(errno));
      break;
    }
    
    if ((error = getnameinfo((SA *) &clientaddr, clientlen, client_hostname, 
          MAXLINE, client_port, MAXLINE, 0)) < 0) {
      fprintf(stderr, "getnameinfo: %s\n", gai_strerror(error));
      break;
    }
    printf("Accepted connection from (%s, %s)\n", client_hostname, client_port);
    doit(conn_fd);
    
    if (close(conn_fd) < 0) {
      fprintf(stderr, "Error closing file: %s\n", strerror(errno));
      exit(1);
    }
  }
  return 0;
}

void doit(int fd) {
  char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE],
       hostname[MAXLINE], path[MAXLINE], url[MAXLINE];
  char port[MAXLINE] = "80";
  char proxy_request[MAXLINE*2];
  rio_t rio;
  rangeNode range = {0, 0, 0};

  /* Read request line and headers */
  rio_readinitb(&rio, fd);
  
  if (rio_readlineb(&rio, buf, MAXLINE) < 0) {
    fprintf(stderr, "RIO_READLINEB ERROR\n");
    exit(-1);
  }
  printf("Request headers:\n");
  printf("%s", buf);
  sscanf(buf, "%s %s %s", method, uri, version);


  if (strcasecmp(method, "GET")) {
    /* Error handling */
    printf("Not Implemented\n\n");
    return;
  }

  get_url(uri, url);
  
  parse_uri(uri, hostname, path, port); 
  if (read_requesthdrs(&rio, buf, hostname, path, proxy_request, &range) < 0) {
    return;
  }
  printf("%s", proxy_request);

  /*Sending request to server */
  if (send_request(fd, proxy_request, port, hostname, url, &range) < 0 ) {
    return;
  }
}

int read_requesthdrs(rio_t *rp, char buf[], char *hostname, char *path,
    char *proxy_request, rangeNode *nodePtr) {
  char *temp;

  /* Creating the GET request header */
  strcpy(proxy_request, "GET ");
  strcat(proxy_request, path);
  strcat(proxy_request, " HTTP/1.0\r\n");

  /* Editing the client request headers if they come */
  while (strcmp(buf, "\r\n")) {
    if (rio_readlineb(rp, buf, MAXLINE) < 0) {
      fprintf(stderr, "RIO_READLINEB ERROR\n");
      return -1;
    }

    if (strstr(buf, "User-Agent:")) {
      strcat(proxy_request, user_agent_hdr);
    } else if (strstr(buf, "Host:")) {
      temp = strstr(buf, "Host: ");
      temp += strlen("Host: ");
      strcpy(temp, hostname);
      strcat(temp, "\r\n");
      strcat(proxy_request, buf);
    } else if(strstr(buf, "Proxy-Connection:")) {
      temp = strstr(buf, ":");
      temp += 1;
      strcpy(temp, " close\r\n");
      strcat(proxy_request, buf);
    } else if (strstr(buf, "Connection:")) {
      temp = strstr(buf, ":");
      temp += 1;
      strcpy(temp, " close\r\n");
      strcat(proxy_request, buf);
    } else if (strstr(buf, "Range:")) {
      process_range(buf, nodePtr);
    } else {
      strcat(proxy_request, buf);
    } 
  }

  /*Adding Headers if they are missing*/
  if (strstr(proxy_request, "\r\nConnection:") == NULL) {
    temp = strstr(proxy_request, "\r\n\r\n");
    temp += strlen("\r\n");
    strcpy(temp, "Connection: close\r\n\r\n"); 
  }

  return 0;
}

void process_range(char *buf, rangeNode *nodePtr) {
  char *next_tok;
  int r1, r2;
  if ((next_tok = strstr(buf, "bytes=")) != NULL) {
    next_tok += 6;
    if (sscanf(next_tok, "-%u", &r1) == 1) {
      nodePtr->type = 3;
      nodePtr->first = -r1;
    } else if ((sscanf(next_tok, "%u-%u", &r1, &r2)) == 2) {
      nodePtr->type = 1;
      nodePtr->first = r1;
      nodePtr->second = r2;
    } else if (sscanf(next_tok, "%u-", &r1) == 1) {
      nodePtr->type = 2;
      nodePtr->first = r1;
    } else {
      nodePtr->type = 0;
      printf("get range: error\n");
      return;
    }
  }
  return;
}

void parse_uri(char *uri, char *hostname, char *path, char *port) {
  char *temp, *temp2;
  temp = strstr(uri, "//"); 

  if (temp != NULL) {
    temp += 2;
    temp2 = strpbrk(temp, "/");

    if (temp2 != NULL) {
      sscanf(temp2, "%s", path);
      strcpy(temp2, "\0");
    }
    
    temp2 = strpbrk(temp, ":");
    if (temp2 != NULL) {
      temp2 += 1;
      sprintf(port, "%s", temp2);
      strcpy(temp2-1, " ");
    }

    sscanf(temp, "%s", hostname);
  } else {
    /* Figure out cache entry for when there is no http */
    hostname = uri;
  }
}

int send_request(int clientfd, char *proxy_request, char *port, char *hostname,
     char *url, rangeNode *nodePtr) { 
  int fd, size;
  char buf[MAXLINE], data[MAXLINE], save_header[MAXLINE], range_header[MAXLINE],
       save_data[MAX_OBJECT_SIZE];
  char *temp;
  int content_length;
  rio_t rio;

  content_length = 0;

  /* Clear out data */
  memset(buf, 0, MAXLINE);
  memset(data, 0, MAXLINE);
  memset(save_header, 0, MAXLINE);
  memset(save_data, 0, MAX_OBJECT_SIZE);
  memset(range_header, 0, MAXLINE);
  
  /* Checks cache for url */
  if (entry->url) {
    if(!strcmp(entry->url, url)) {
      //write response headers to client 
      if (nodePtr->type != 0) {
        edit_response(entry->response_header, range_header, nodePtr);
        printf("%s", range_header);
        
        if (rio_writen(clientfd, range_header, strlen(range_header)) < 0) {
          fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
          return -1;
        }

        /* Writing data */
        content_length = (nodePtr->second-nodePtr->first) + 1;
        if (rio_writen(clientfd, &entry->file_buf[nodePtr->first], 
              content_length) < 0) {
          fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
          return -1;
        }

      } else {
        /* Non-Range Request */
        printf("%s", entry->response_header);
        
        if (rio_writen(clientfd, entry->response_header, 
            strlen(entry->response_header)) < 0 ) {
          fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
          return -1;
        }

        //write data to client 
        if (rio_writen(clientfd, entry->file_buf, entry->content_length)<0) {
          fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
          return -1;
        }
      } 
      return 0;
    }
  } 
  
  /* Starting Transaction with Host */
  if ((fd = open_clientfd(hostname, port)) < 0) {
    fprintf(stderr, "open_clientfd error: %s\n", strerror(errno));
    return -1;
  }

  if (rio_writen(fd, proxy_request, strlen(proxy_request)) < 0) {
    close(fd);
    fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
    return -1;
  }
    
  /* Read and Write Response Headers */
  rio_readinitb(&rio, fd);
  if (rio_readlineb(&rio, buf, MAXLINE) < 0 ) {
    close(fd);
    fprintf(stderr, "rio_readlineb error: %s\n", strerror(errno));
    return -1;
  }
  strncat(save_header, buf, strlen(buf));
  
  while(strcmp(buf, "\r\n")) {
    if (rio_readlineb(&rio, buf, MAXLINE) < 0) {
      close(fd);
      fprintf(stderr, "rio_readlineb error: %s\n", strerror(errno));
      return -1;
    }
    strncat(save_header, buf, strlen(buf));
  } 

  /* Editing, Printing, and Writing Response Headers */
  edit_response(save_header, range_header, nodePtr);
  printf("%s", range_header);
  if (rio_writen(clientfd, range_header, strlen(range_header)) < 0) {
    close(fd);
    fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
    return -1;
  }

  /* Continuous write data to client */
  temp = save_data;
  while ((size = rio_readnb(&rio, data, MAXLINE)) != 0) {
    if (size < 0) {
      close(fd);
      fprintf(stderr, "rio_readnb error: %s\n", strerror(errno));
      return -1;
    }

    content_length += size;
    if (nodePtr->type == 0) {
      if (rio_writen(clientfd, data, size) < 0) {
        close(fd);
        fprintf(stderr, "rio_writen error: %s\n", strerror(errno));
        return -1;
      }
    }
    
    if (content_length <= MAX_OBJECT_SIZE) {
      memcpy(temp, data, size);
      temp += size;
    }
  } 
    
  create_entry(content_length, url, save_header, save_data);
  
  /* Writes range data resposne */
  if (nodePtr->type != 0) {
    rio_writen(clientfd, &save_data[nodePtr->first], 
        (nodePtr->second-nodePtr->first)+1);
  }
  close(fd);
  return 0;
}

/* Using code previous written in hw8
 * Checking for type of range and if the range is valid
 * returns a range_length who's default value is set to c_length
 * Will set valid to 1 if it is a valid range request*/
int valid_range(rangeNode *nodePtr, int c_length, int valid) {
  int range_length = c_length;
  int r1 = nodePtr->first;
  int r2 = nodePtr->second;

  if (nodePtr->type == 0) {
    nodePtr->first = 0;
    nodePtr->second = c_length-1;
    return c_length;
  } else if (nodePtr->type == 1) {
    valid = nodePtr->first >= c_length ? 0: 1;
    valid = nodePtr->second > nodePtr->first ? 1 : 0;
    nodePtr->second = nodePtr->second >= c_length ? c_length-1 : nodePtr->second;
    range_length = valid ? (r2 - r1) + 1 : range_length;
  } else if (nodePtr->type == 2) {
    valid = r1 < c_length ? 1 : 0;
    nodePtr->first = nodePtr->first < 0 ? 0 : r1;
    nodePtr->second = c_length - 1;
    range_length = valid ? (c_length - r1) : range_length;
  } else {
    valid = (-r1) > c_length ? 0 : 1;
    nodePtr->first = valid ? c_length + r1 : 0;
    nodePtr->second = c_length - 1;
    range_length = (c_length - nodePtr->first);
  }
  return range_length;
}

void get_url(char *uri, char *url) {
  char *temp;

  temp = strstr(uri, "//");
  temp += 2;
  sprintf(url, "%s", temp);
  
  return;
}

/* Saves entry to cache if file does not exceed max limit */
void create_entry(int content_length, char *url, char *save_header,
    char *save_data) { 
 /* Checking if filesize of data is larger than MAX_OBJECT_SIZE */
  if (content_length <= MAX_OBJECT_SIZE) {  
    if (entry->url) {
      free(entry->url);
      free(entry->response_header);
      memset(entry->file_buf, 0, sizeof(entry->file_buf));
    }
    entry->url = strndup(url, strlen(url));
    //entry->response_header = strndup(save_header, strlen(save_header));
    entry->response_header = (char*)malloc(strlen(save_header));
    strcpy(entry->response_header, save_header);
    memcpy(entry->file_buf, save_data, content_length);
    entry->content_length = content_length;
  }
}

void edit_response(char *save_header, char *range_header, rangeNode *nodePtr) {
  int valid = 0;
  int c_length = 0;
  int range_length = 0;
  char content_range[MAXLINE];
  char content_length[MAXLINE];

  char *temp;

  if ((temp = strstr(save_header, "Content-length:")) != NULL) {
    temp += strlen("Content-length: ");
    sscanf(temp, "%d", &c_length);
  }
  
  range_length = valid_range(nodePtr, c_length, valid);
  sprintf(content_range, "Content-Range: bytes %d-%d/%d\r\n", 
      nodePtr->first, nodePtr->second, c_length);
  sprintf(content_length, "Content-length: %d\r\n", range_length);

  if (nodePtr->type == 0) {
    memcpy(range_header, save_header, strlen(save_header));
    return;
  } else {
    strcpy(range_header, "HTTP/1.0 206 Partial Content\r\n");
    strcat(range_header, "Server: Tiny Web Server\r\n");
    strcat(range_header, content_range);
    strcat(range_header, content_length);
    strcat(range_header, "Content-type: text/html\r\n\r\n");
  }
  return;
}
