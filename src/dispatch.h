#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(u_char *verb, struct pcap_pkthdr *header, 
              const unsigned char *packet
              );

void sighandle(int signl);
void t_init();
#endif
