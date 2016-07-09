#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

struct sockaddr_in source,dest;

void process(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(){
	const char *dev = "eth0";
	char error_buf[100];
	pcap_t *handle;
	handle = pcap_open_live(dev , 65536 , 1 , 0 , error_buf);
         
	if (handle == NULL) {
		printf("error with %s : %s\n" , dev , error_buf);
		exit(1);
    	}
	pcap_loop(handle , -1 , process, NULL);
	printf("pCAP");
}

void process(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){
	int size = header->len;
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol) { 
        case 6:
		{
		unsigned short iphdrlen;
		struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
		iphdrlen = iph->ihl*4;

        	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
        	struct ethhdr *eth = (struct ethhdr *)buffer; 
        	memset(&source, 0, sizeof(source));
        	source.sin_addr.s_addr = iph->saddr;
        	memset(&dest, 0, sizeof(dest));
        	dest.sin_addr.s_addr = iph->daddr;
        	printf("SourceMac : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
        	printf("DestMac : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
        	printf("Source IP : %s\n" , inet_ntoa(source.sin_addr) );
        	printf("Dest IP : %s\n" , inet_ntoa(dest.sin_addr) );
        	printf("Source Port: %u\n",ntohs(tcph->source));
        	printf("Dest Port: %u\n",ntohs(tcph->dest));
            break;
}
        default:
           
            break;
    }

}
















