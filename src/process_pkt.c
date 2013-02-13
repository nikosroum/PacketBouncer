#include "bouncer.h"
void printList(){
   struct Node *cur_ptr;    
   cur_ptr=Head; 
 
   while(cur_ptr != NULL)  
   {  
      printf("ip:%s,srcport:%d,bport:%d\n",cur_ptr->address,cur_ptr->src_port,cur_ptr->bounce_port);
         cur_ptr=cur_ptr->Next;  
   }  

}
unsigned short get_tcp_checksum(struct ip * myip, struct tcphdr * mytcp) {
	
		struct tcp_pseudo pseudohead;
        unsigned int total_len = ntohs(myip->ip_len);
		int size_ip=(myip->ip_hl*4);
		int tcpopt_len = mytcp->th_off*4 - size_ip;
		int tcpheaderlength= sizeof(struct tcphdr);
        

			
		int tcpdatalen = total_len - (mytcp->th_off*4) - size_ip ;
		/*
		if (mytcp->th_off%2==1){
		printf("odd number-padding needed\n!");
		* //to do
		}*/
		
        pseudohead.src_addr=myip->ip_src.s_addr;
        pseudohead.dst_addr=myip->ip_dst.s_addr;
        pseudohead.zero=htons(0);
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(tcpheaderlength + tcpopt_len + tcpdatalen);
        
		//set checksum = 0 
		mytcp->th_sum=htons(0);
		
        int pseudo_len = sizeof(struct tcp_pseudo) + tcpheaderlength + tcpopt_len + tcpdatalen;
         
        //buffer for the new pseudo tcp segment
        unsigned short * checktcp = (unsigned short *) malloc(pseudo_len * sizeof (unsigned short));
		
		memcpy((unsigned char *)checktcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)checktcp+sizeof(struct tcp_pseudo),(unsigned char *)mytcp,tcpheaderlength);
        memcpy((unsigned char *)checktcp+sizeof(struct tcp_pseudo)+tcpheaderlength, (unsigned char *)myip+(myip->ip_hl*4)+tcpheaderlength, tcpopt_len);
        memcpy((unsigned char *)checktcp+sizeof(struct tcp_pseudo)+tcpheaderlength+tcpopt_len, (unsigned char *)mytcp+(mytcp->th_off*4), tcpdatalen);

 
        printf("tcp hdr length: %u\n",mytcp->th_off);
        printf("tcp total+psuedo length: %d\n",pseudo_len);
		
        printf("tcp data len: %d\n", tcpdatalen);
		
		return in_cksum((unsigned short *)checktcp,pseudo_len);

}

void process_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){

    /* Define pointers for packet's attributes */
	
	static int count = 1; /* packet counter */
	char *client_address;
    /* declare pointers to packet headers */
   
    struct ip *ip; /* The IP header */
    struct icmp *icmp; /* The TCP header */
    
	u_short checksum,checksum2;
    int size_icmp;
    int size_ip;
    int size_payload;
char buffer[BUFFERSIZE];
	memset(buffer, 0, BUFFERSIZE);
    printf("\nPacket number %d:\n", count);
    count++;

/* Check IP header*/
	ip = (struct ip*) (packet + sizeof(struct ethhdr));
    size_ip = ip->ip_hl*4;
    /*check for valid IP header size*/
    if (size_ip < 20 || size_ip > 60) {
        printf("Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    /*check for evil bit*/
    if (ntohs(ip->ip_off)==IP_RF){
			printf("Evil Bit set\n");
			return;
		}		
    /*Check for valid IP version*/
    if (ip->ip_v!=4){
			printf("Invalid IP version\n");
			return;
		}
		/*Check for TTL field*/
		if (ip->ip_ttl==0){	
			printf("TTL=0\n");
			return;
		}
	checksum=ip->ip_sum;
	ip->ip_sum=0;
	checksum2=in_cksum((unsigned short *)ip,size_ip);
	ip->ip_sum=checksum2;
  
	/*Check for checksum*/
		if(checksum!=checksum2){
			printf("Different IP checksum, packet will be dropped!\n");
			return;	
		}
		  /* print source and destination IP addresses */
    	printf("       From: %s\n", inet_ntoa(*(struct in_addr*)&ip->ip_src));
    	printf("         To: %s\n", inet_ntoa(*(struct in_addr*)&ip->ip_dst));
/* Check type of packet and process*/
int prototype;
switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
			prototype=1;
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
			prototype=2;
            break;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
			prototype=3;
            break;

        default:
            printf("   Protocol: unknown\n");
            return;
    }
    if(prototype==1){
				struct tcphdr *tcpheader;
				tcpheader =(struct tcphdr*)(packet +sizeof(struct ethhdr)+size_ip);
				
				if (tcpheader->th_off*4<20){	
					printf("TCP header length minimum!\n");
					return;
				}
				
				checksum = tcpheader->th_sum;
				tcpheader->th_sum=0;
				checksum2 = get_tcp_checksum(ip,tcpheader) ;
				tcpheader->th_sum=  checksum2 ;

				if (checksum!=checksum2){
					printf("TCP invalid checksum!\n");
					return;
				}
				
				if (strcmp(inet_ntoa(ip->ip_src),server_ip)==0){//Server sent
					printf("server---bouncer\n");
					printf("From %s to port %u\n",inet_ntoa(ip->ip_src),htons(tcpheader->th_dport));
					struct Node * res = searchTCP(ntohs(tcpheader->th_dport));
					if(res==NULL){
						printf("Not in the list\n");
						return;
					}
					inet_aton(listen_address,&(ip->ip_src));
					inet_aton(res->address,&(ip->ip_dst));
					printf("creating IP packet..\n");
					//recalculate IP checksum
					ip->ip_sum=0;
					ip->ip_sum=in_cksum((unsigned short *)ip,size_ip);
					
					tcpheader->th_sport=htons(listen_port);
					tcpheader->th_dport=htons(res->src_port);
					tcpheader->th_sum=htons(0);
					tcpheader->th_sum=get_tcp_checksum(ip,tcpheader);
				}else//client request
				{	//check for listen port
					if(ntohs(tcpheader->th_dport)!=listen_port){
						printf("Different from listen port\n");
						return;
					}
					printf("Packet from client\n");
					struct Node * res = searchSrcTCP(ntohs(tcpheader->th_sport),inet_ntoa(ip->ip_src));
					if(res==NULL && tcpheader->th_flags==TH_SYN){
						printf("Not in the list\n");
						Bounce_port++;
						addTCPtoList(ntohs(tcpheader->th_sport),Bounce_port,inet_ntoa(ip->ip_src));
						printList();
						tcpheader->th_sport=htons(Bounce_port);
						printf("tcp new header->dport=%u\n",ntohs(tcpheader->th_dport));
					}else{
						tcpheader->th_sport=htons(res->bounce_port);
						}
					//change IP addresses
					inet_aton(listen_address,&(ip->ip_src));
					inet_aton(server_ip,&(ip->ip_dst));
					printf("creating IP packet..\n");
					//recalculate IP checksum
					ip->ip_sum=0;
					ip->ip_sum=in_cksum((unsigned short *)ip,size_ip);
					tcpheader->th_dport=htons(server_port);
					
					tcpheader->th_sum=0;
					tcpheader->th_sum=get_tcp_checksum(ip,tcpheader);
				}
				 printf("Source IP: %s\n",inet_ntoa(*(struct in_addr*)&ip->ip_src));
				 printf("Dst IP: %s\n",inet_ntoa(*(struct in_addr*)&ip->ip_dst));
				 printf("Sport=%u\n",ntohs(tcpheader->th_sport));
				 printf("Dport=%u\n",ntohs(tcpheader->th_dport));
				
				if(sendIPpacket(ip,inet_ntoa(*(struct in_addr*)&ip->ip_dst),htons(tcpheader->th_sport))<0){
					printf("Error occured while sending!\n");
					return;
				}
				return;
	}//end of tcp
    if(prototype==2){
		 icmp = (struct icmp*) (packet + size_ip + sizeof(struct ethhdr));
        checksum=icmp->icmp_cksum;
        icmp->icmp_cksum=0;
        checksum2=in_cksum((unsigned short *) icmp, sizeof (struct icmp)*8);
        icmp->icmp_cksum=checksum2;
        if(checksum!=checksum2){
			printf("%d\t%d\nDifferent ICMP checksum, packet will be dropped!\n",checksum,checksum2);
			return;	
		}
		if(icmp->icmp_hun.ih_idseq.icd_id < 0 || icmp->icmp_hun.ih_idseq.icd_id > 65535){
			printf("Bad ICMP ID\n");
			return;
		}
		if (icmp->icmp_type == ICMP_ECHO && icmp->icmp_code==0) {
			client_address=(char *)malloc(32*sizeof(char));
			strcpy(client_address , inet_ntoa(*(struct in_addr*)&ip->ip_src));
			//add to reqlist
			addtoList(icmp->icmp_hun.ih_idseq.icd_id,client_address);
			
			printf("ECHO_request received\n");
			printf("ICMP: type[%d/%d] checksum[%d] \n\n\n",
			icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum));
			
			inet_aton(listen_address,&(ip->ip_src));
            inet_aton(server_ip,&(ip->ip_dst));
            /*recalculate checksum*/
            ip->ip_sum=0;
            ip->ip_sum=in_cksum((unsigned short *)ip,size_ip);
			if(sendIPpacket(ip,server_ip,0)<0){
				printf("Error occured while sending!\n");
				return;
			}
            return;
			
		}//end for request
		else if (icmp->icmp_type == 0 && icmp->icmp_code==0) {
			
			printf("Client Address=%s\n",client_address);
			printf("ICMP_reply received\n");
			printf("       From: %s\n", inet_ntoa(*(struct in_addr*)&ip->ip_src));
			printf("         To: %s\n", inet_ntoa(*(struct in_addr*)&ip->ip_dst));
			printf("ICMP: type[%d/%d] checksum[%d] \n\n\n",
			icmp->icmp_type, icmp->icmp_code, ntohs(icmp->icmp_cksum));
			client_address=search(icmp->icmp_hun.ih_idseq.icd_id);
			if(client_address==NULL){
				return;}
			ip->ip_src=ip->ip_dst;
			
			inet_aton(client_address,&(ip->ip_dst));
			
			ip->ip_sum=0;
			ip->ip_sum=in_cksum((unsigned short *)ip,size_ip);
			printf("\npacket done!\n");
			if(sendIPpacket(ip,client_address,0)<0){
				printf("Error occured while sending!\n");
				return;
			}
			return;
			
			
			
			
		}else{
			printf("ICMP Error Code!\n");
			return;
		}
	}//end of prototype==2




}//end of function

int sendIPpacket ( struct ip * ip , char * address ,unsigned int  dstport)
{
			struct sockaddr_in connection;
            int sockfd;
            int optval;
            int siz;
            int size_ip = ip->ip_hl*4;
			
			/*Set Raw Socket*/
			if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
                perror("socket");
                exit(EXIT_FAILURE);
            }

            /*
             * IP_HDRINCL must be set on the socket so that
             * the kernel does not attempt to automatically add
             * a default ip header to the packet
             */
           
           
           setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof (int));
           memset(&connection, 0, sizeof(connection));
            connection.sin_family = AF_INET;
            if(dstport!=0){
				connection.sin_port = htons(dstport);
				printf("Bouncer:Sending from=%hu \n\n",ntohs(connection.sin_port ));
           }
            connection.sin_addr.s_addr = inet_addr(address);/*destination address*/
           
           //we will not send the whole packet as it contains the ethernet frame also
          
           if(sendto(sockfd, ip, ntohs(ip->ip_len), 0, (struct sockaddr *) &connection, sizeof (struct sockaddr))<0){
			   perror("sendto");
				return -1;
		    }
            
            close(sockfd);
            return 1;
	
}
