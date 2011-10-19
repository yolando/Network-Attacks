#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <libnet.h>
/*
 * Simple tcp client for use in tcp reset attack testing.
 *
 * Execute as follows: ./client  server_address server_port client_port input_file
 *
 */


int main(int argc, char **argv)
{	
  char *cli_port;
  char *srv_addr;
  char *cli_addr;
  char *srv_port;
  char *input_file;
  //char *message = "This is the future!";	//test message
  char line[128];

  struct sockaddr_in server, client;
  struct addrinfo hints, *res;
  int sock_fd, length;
  int data_sent=0;
  //socklen_t addr_size;		   //no use
  //struct sockaddr_storage server_addr;   //no use


  
  if (argc >= 2) {
      srv_addr = argv[1];
  } else {
      srv_addr = "127.0.0.1";
  }
  
  if (argc >= 3) {
      srv_port = argv[2];
  }
  else {
      srv_port = "9999";
  }

  if(argc >= 4) {
      cli_port = argv[3];
  } else {
      cli_port = "10001";
  }

  if(argc >= 5) {
      input_file = argv[4];
  } else {
      input_file = "junk";
  }
  
  cli_addr = "127.0.0.1";

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  FILE *file_handler = fopen(input_file,"r");
  getaddrinfo(cli_addr, cli_port, &hints, &res);  
  sock_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

  memset(&client, 0, sizeof (struct sockaddr_in));
  client.sin_family = AF_INET;
  client.sin_port = atoi(argv[3]);
  //client.sin_addr.s_addr = inet_addr(LOCAL_IP_ADDRESS);

  bind(sock_fd, res->ai_addr, res->ai_addrlen); 
 
  getaddrinfo(srv_addr, srv_port, &hints, &res);  
  							//  getaddrinfo(srv_addr, srv_port, &hints, &res);  
  memset(&server, 0, sizeof (struct sockaddr_in));
  server.sin_family = AF_INET;
  server.sin_port = atoi(argv[2]);
  server.sin_addr.s_addr = inet_addr(srv_addr);

  connect(sock_fd, res->ai_addr, res->ai_addrlen);
  
  printf("starting client using port %s, connecting to server %s:%s, reading file %s\n",
		  cli_port, srv_addr, srv_port, input_file);

  while(fgets(line, 128, file_handler)!=NULL)			// and connection not r
   {
    //sscanf(line,"%s");
    length = strlen(line);  
    data_sent = write(sock_fd, line, length);
    //printf("Data sent: %d\nLength of line: %d\nLine Sent: %s\nClient Port: %s\n", data_sent, length, line, cli_port);
/*    if(data_sent == -1)
     {
      printf("%s\n",errbuf);
     }*/
    printf("%d\n", data_sent);
    sleep(1);
   }
  
  printf("test3: %d \n", sock_fd);
  fclose(file_handler);
  close(sock_fd);
  return 0;
}

 
