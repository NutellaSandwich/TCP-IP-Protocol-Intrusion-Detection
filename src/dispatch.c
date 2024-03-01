#include "dispatch.h"

#include <pcap.h>
#include "sniff.h"
#include "analysis.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "queue.h"

extern unsigned long syn;
extern unsigned long uniqip;
extern unsigned long arp;
extern unsigned long black;
extern unsigned long goog;
extern unsigned long face;
pthread_t threads[100];

struct queue *work_queue;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

char done=0;




void dispatch(u_char *verb,struct pcap_pkthdr *header,
              const unsigned char*packet
              ) {
  int verbose = (int) *verb;
  if(verbose){
    dump(packet, header->len);
    analyse(packet, verbose);
  }else{
    pthread_mutex_lock(&queue_mutex);
    pthread_cond_broadcast(&queue_cond);
    enqueue(work_queue, packet);
  //analyse(header, packet, verbose);
    pthread_mutex_unlock(&queue_mutex);
  }
}



void sighandle (int signl){
  
  if (signl == SIGINT){
    done=1;
    pthread_cond_signal(&queue_cond);
    void *retval;
    int i = 0;
    for(i=0;i<10;i++){
      pthread_join(threads[i],&retval);
    }
    int x=0;
    for(x=0;x<10;x++){
      pthread_detach(threads[i]);
    }
  } 
}

void *thread_code(void *arg){
  const unsigned char* packe = NULL;
  signal(SIGINT, sighandle);
  while(!done){
    
    pthread_mutex_lock(&queue_mutex);
    while(isempty(work_queue) & !done){
      pthread_cond_wait(&queue_cond,&queue_mutex);
    }

    if(!isempty(work_queue)){
      packe = dequeue(work_queue);
      //pthread_mutex_unlock(&queue_mutex);

      if(packe!=NULL){
        analyse(packe, 0);
    } 
    }
    pthread_mutex_unlock(&queue_mutex);
  }
  
  printf("\n Intrusion Detection Report:");
  printf("\n %ld SYN packets detected from %ld different IPs (syn attack)", syn, uniqip);
  printf("\n %ld ARP responses (cache poisoning)", arp);
  printf("\n %ld URL Blacklist violations (%ld google and %ld facebook)\n", black, goog, face);
  exit(EXIT_SUCCESS);
  return NULL;
}

void t_init(){
  work_queue = create_queue();
  done=0;
  int i;
  for (i=0; i<100; i++){
    pthread_create(&threads[i], NULL, &thread_code, (void *) NULL);
  }
}