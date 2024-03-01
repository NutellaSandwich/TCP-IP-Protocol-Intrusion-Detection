#include <stdio.h>
#include <stdlib.h>
#include "queue.h"

struct queue *create_queue(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  q->head=NULL;
  q->tail=NULL;
  return(q);
}


int isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, const unsigned char *item){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node)); 
  new_node->item=item;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

const unsigned char * dequeue(struct queue *q){ //dequeues a the head node

  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    const unsigned char * ret= head_node->item;
    q->head=q->head->next;
    if(q->head==NULL){
      q->tail=NULL;
    }
    free(head_node);
    return ret;
  }
  return 0;
}
