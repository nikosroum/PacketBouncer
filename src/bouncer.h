/* Global definitions for the port bouncer
 * Packet headers and so on
 */

#define _BSD_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* PCAP declarations */
#include <pcap.h>

/* Standard networking declaration */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
/*
 * The following system include files should provide you with the 
 * necessary declarations for Ethernet, IP, and TCP headers
 */

#include <netdb.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

/* Add any other declarations you may need here... */
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
#define BUFFERSIZE 65533
unsigned short listen_port;
unsigned short server_port;
char *listen_address;
char *server_ip;
unsigned short Bounce_port;
struct Node{  
	  /*For ICMP multiping*/
      unsigned short int id;
      
      /*for TCP session identification*/
	  unsigned short src_port;
  	  unsigned short bounce_port;
      
      char* address;
      struct Node *Next;  
}*Head;  

char *buffer[BUFFERSIZE];
#define IP_HL(ip)               (((ip)->ihl) & 0x0f)
#define IP_V(ip)                (((ip)->version) >> 4)

/* TCP header */
struct tcp_pseudo /*the tcp pseudo header*/
{
  unsigned int src_addr;
  unsigned int dst_addr;
  unsigned char zero;
  unsigned char proto;
  unsigned short int length;
};

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

char *search(unsigned short int id);

void  delfromList(unsigned short int id);
 /*THIS FUNCTION ADDS A NODE AT THE LAST OF LINKED LIST */

void addtoList(unsigned short int id ,char * address);
struct Node * searchTCP(unsigned short bport);
void addTCPtoList(unsigned short int sport,unsigned short int bport,char* address);
struct Node * searchSrcTCP(unsigned short bport,char * client_address);

