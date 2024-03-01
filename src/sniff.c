#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include "dispatch.h"
#include "queue.h"



// Application main sniffing loop
void sniff(char *interface, int verbose) {
  
  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  
  if(!verbose){
    t_init();
  } 
  signal(SIGINT, sighandle);
  pcap_loop(pcap_handle,-1,(pcap_handler)dispatch,(u_char *) &verbose);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
signal(SIGINT, sighandle);
  printf("\nType: %hu\n", ntohs(eth_header->ether_type));

  

  struct ip *iheader = (struct ip *)(data+ETH_HLEN);
  printf("\n === IP HEADER === ");
  printf("\n Version: %02x", iheader->ip_v);
  printf("\n IHL: %02x", iheader->ip_hl);
  printf("\n ToS: %02x", iheader->ip_tos);
  printf("\n Length: %hu", iheader->ip_len);
  printf("\n Identification: %hu", ntohs(iheader->ip_id));
  printf("\n Flag: %02x", ntohs(iheader->ip_off));
  printf("\n Time: %02x", iheader->ip_ttl);
  printf("\n Protocol: %02x", iheader->ip_p);
  printf("\n CheckSum: %hu", iheader->ip_sum);
  
  printf("\n Source IP: %s", inet_ntoa(iheader->ip_src));
  
  printf("\n Destination IP: %s", inet_ntoa(iheader->ip_dst));

    

  struct tcphdr *theader = (struct tcphdr *)(data+ETH_HLEN+iheader->ip_hl*4);
  printf("\n === TCP HEADER === ");
  printf("\n Source Port: %hu",ntohs(theader->source));
  printf("\n Destination Port: %hu",ntohs(theader->dest));
  printf("\n Sequence Number: %hu",ntohs(theader->seq));
  printf("\n Acknowledgment Number: %hu",ntohs(theader->ack_seq));
  printf("\n Data Offset: %hu", theader->doff);
  printf("\n Window: %hu", theader->window);
  printf("\n Checksum: %hu", theader->check);
  printf("\n Urgent Pointer: %hu", ntohs(theader->urg_ptr));
  
  printf("\n === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN - iheader->ip_hl*4-theader->doff*4;
  const unsigned char *payload = data + ETH_HLEN+iheader->ip_hl*4+theader->doff*4;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
    }

  pcount++;
}
