

   struct node
 {
   	
   unsigned int id;//icmp
   char* address;
   struct node *next;
 }*p;



   void  delfromList(int id,char * address);
 /*THIS FUNCTION ADDS A NODE AT THE LAST OF LINKED LIST */

    void addtoList( int id ,char * address);
  
 /* THIS FUNCTION DISPLAYS THE CONTENTS OF THE LINKED LIST */

  void display(struct node *r);
//THIS FUNCTION COUNTS THE NUMBER OF ELEMENTS IN THE LIST
int count();
