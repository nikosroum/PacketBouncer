#include "bouncer.h"


 /*THIS FUNCTION DELETES A NODE */

//search client address
//delete id,client address
char *search(unsigned short int id){
	 struct Node *prev_ptr, *cur_ptr;    
   cur_ptr=Head; 
   char* res=NULL;
  
   while(cur_ptr != NULL)  
   {  
      if(cur_ptr->id == id)  
      {  
         if(cur_ptr==Head)  
         {  
	    res=malloc(sizeof(cur_ptr->address));
            strcpy(res,cur_ptr->address);
            //Head=cur_ptr->Next;  
             //free(cur_ptr);  
            return res;  
         }  
         else  
         {  
	    res=malloc(sizeof(cur_ptr->address));
            strcpy(res,cur_ptr->address);
            prev_ptr->Next=cur_ptr->Next;  
           //free(cur_ptr);  
            return res;  
         }  
      }  
      else  
      {  
         prev_ptr=cur_ptr;  
         cur_ptr=cur_ptr->Next;  
      }  
   }  
  
   printf("\nElement: id %d is not found in the List\n", id);  
   return res;  
}  


	
void delfromList(unsigned short int id)  
{  
   struct Node *prev_ptr, *cur_ptr;    
   cur_ptr=Head; 
   char* res=NULL;
  
   while(cur_ptr != NULL)  
   {  
      if(cur_ptr->id == id)  
      {  
         if(cur_ptr==Head)  
         {  
	             Head=cur_ptr->Next;  
            free(cur_ptr);  
            return;  
         }  
         else  
         {  
	   
            prev_ptr->Next=cur_ptr->Next;  
            free(cur_ptr);  
            return;  
         }  
      }  
      else  
      {  
         prev_ptr=cur_ptr;  
         cur_ptr=cur_ptr->Next;  
      }  
   }  
  
   printf("\nElement: id %d is not found in the List\n", id);  
   return ;  
}  

/*THIS FUNCTION ADDS A NODE AT THE LAST OF LINKED LIST */

void addtoList(unsigned short int id,char* address)  
{  
   struct Node *temp;  
   temp=(struct Node *)malloc(sizeof(struct Node));  
   temp->id = id;  
   
   temp->address=malloc(64);
   
   strcpy(temp->address,address);
   printf("Added to List id=%d address=%s",temp->id,temp->address);
  
   if (Head == NULL)  
   {  
      Head=temp;  
      Head->Next=NULL;  
   }  
   else  
   {  
      temp->Next=Head;  
      Head=temp;  
   }
     
}  
/***************************************/
 void addTCPtoList(unsigned short sport,unsigned short bport,char* address)  
{  
   struct Node *temp;  
   temp=(struct Node *)malloc(sizeof(struct Node));  
   temp->src_port = sport;  
   temp->bounce_port = bport;  
   temp->address=malloc(64);
   
   strcpy(temp->address,address);
   printf("\nAdded to List address=%s port=%u \n",temp->address,temp->src_port);
  
   if (Head == NULL)  
   {  
      Head=temp;  
      Head->Next=NULL;  
   }  
   else  
   {  
      temp->Next=Head;  
      Head=temp;  
   }
     
}  
struct Node * searchTCP(unsigned short bport){
   struct Node *cur_ptr;    
   cur_ptr=Head; 
  printf("Searching : %u\n",bport);
   while(cur_ptr != NULL)  
   {  printf("Found %u\n",cur_ptr->bounce_port);
      if(cur_ptr->bounce_port == bport)  
      {
	 return cur_ptr;
      }
         cur_ptr=cur_ptr->Next;  
   }  
   printf("Not found--------------------------\n");
   return NULL;    
}  
/*Search for same src port*/
struct Node * searchSrcTCP(unsigned short sport,char * client_address){
	struct Node *cur_ptr;    
    cur_ptr=Head; 
   
   while(cur_ptr != NULL)  
   {  
      if(cur_ptr->src_port == sport && !strcmp(client_address,cur_ptr->address))  
      {
		return cur_ptr;
      }
         cur_ptr=cur_ptr->Next;  
   }  
   return NULL;  
}  
