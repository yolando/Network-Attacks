#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>


/*
 * Simple tcp server to test the tcp reset attack.
 *
 * Start as follows: ./server  server_ip  server_port
 *
 */

#define BUFFERSIZE 65536

int main(int argc, char **argv) {
  char *srv_addr;
  char *srv_port;
  char buffer[BUFFERSIZE];

  struct addrinfo hints, *res;
  int sock_fd,newsock_fd;
  int data_read=0;
  socklen_t addr_size;
  struct sockaddr_storage client_addr;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (argc >= 2)
   {
    srv_addr = argv[1];
   }
  else 
   {
    srv_addr = "127.0.0.1";
   }

  if (argc >= 3) 
   {
    srv_port = argv[2];
   } 
  else 
   {
    srv_port = "9999";
   }

  getaddrinfo(srv_addr, srv_port, &hints, &res); 

  sock_fd=socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  bind(sock_fd, res->ai_addr, res->ai_addrlen);
  listen(sock_fd, 5);
  printf("starting server at IP %s, listening on port %s\n", srv_addr, srv_port);
  
  addr_size = sizeof client_addr;
  newsock_fd = accept(sock_fd, (struct sockaddr*) &client_addr, &addr_size);

  for(;;)
   {
    data_read = read(newsock_fd, buffer, BUFFERSIZE-1);			//can also use recv here.
    //receive code here
    //if(data_read!=0)
    // {
      printf("%d\n", data_read); 
      if(data_read == -1)
       {
        return 1;
       }
    // }
   }
  close(newsock_fd);
  close(sock_fd);
  return 0;
}

 
