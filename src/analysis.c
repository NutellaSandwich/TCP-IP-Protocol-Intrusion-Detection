#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include "dispatch.h"
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

unsigned long syn = 0;
unsigned long uniqip = 0;
unsigned long arp = 0;
unsigned long black = 0;
unsigned long goog = 0;
unsigned long face = 0;

pthread_mutex_t muxlock = PTHREAD_MUTEX_INITIALIZER;


typedef struct{
  int *arr;
  size_t num;
  size_t size;
}IP;

IP synip;


void initArr(IP *synip, size_t initS){
  synip->arr = malloc(initS*sizeof(int));
  synip->num=0;
  synip->size = initS;

}

void addArr(IP *synip, long element){

  for (int x =0; x <synip->num; x++){
    if (synip->arr[x]==element){
      return;
    }
  } 

  if(synip->num==synip->size){
    synip->size *= 2;
    synip->arr = realloc(synip->arr, synip->size*sizeof(int));
  }
    synip->arr[synip->num++]=element;
    uniqip++;
}


void analyse(
             const unsigned char *packet,
             int verbose) {
  if (synip.num<0){
    initArr(&synip,100);
  }

  struct ether_header *eth_header;
  struct ip *iheader;
  struct tcphdr *theader;
  unsigned char *data;
    eth_header = (struct ether_header *) packet;
    iheader = (struct ip *)(ETH_HLEN+packet);
    theader = (struct tcphdr *)(ETH_HLEN + packet + iheader->ip_hl*4);
    data = ETH_HLEN + packet + iheader->ip_hl*4 + theader->doff*4;

  
  if((theader->syn == 1) && (theader->fin == 0) && (theader->rst == 0) && (theader->psh == 0) && (theader->ack == 0) && (theader->urg == 0)){
    pthread_mutex_lock(&muxlock);
    syn++;
    pthread_mutex_unlock(&muxlock);
    addArr(&synip, inet_addr(inet_ntoa(iheader->ip_src)));
  }

  if(ntohs(eth_header->ether_type)==0x0806){
    pthread_mutex_lock(&muxlock);
    arp++;
    pthread_mutex_unlock(&muxlock);
    
  }

  if (theader != NULL){
    if(ntohs(theader->dest)==80){
      if((strstr((char*)data,"Host: www.google.co.uk")!=NULL) | (strstr((char*)data, "Host: www.facebook.com")!= NULL)){
        if(strstr((char*)data, "Host: www.google.co.uk")!=NULL){
          pthread_mutex_lock(&muxlock);
          goog++;
          pthread_mutex_unlock(&muxlock);
        }
        if(strstr((char*)data, "Host: www.facebook.com")!=NULL){
          pthread_mutex_lock(&muxlock);
          face++;
          pthread_mutex_unlock(&muxlock);
        }
        pthread_mutex_lock(&muxlock);
        black++;
        pthread_mutex_unlock(&muxlock);
        
        printf("\n==============================\n");
        printf("Blacklisted URL violation detected\n");
        printf("Source IP address: %s \n",inet_ntoa(iheader->ip_src));
        printf("Destination IP address %s \n",inet_ntoa(iheader->ip_dst));
        printf("==============================\n");
      }
    }
  }
}


