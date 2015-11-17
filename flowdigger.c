/* Flowdigger was written by Tyler Welton 'spaceB0x'
2015 - Issued under the self termed 'Jesus License'
"Freely you have received; freely give" -Matt 10:8
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nflow.h"
#include "netmeth.h"

/* Typedef to be able to pass 2 parameters to the loop callback function */
struct configStruct{
    int *fd;
    u_char *pktpntr;
};

/* method declarations */
void decode_ethernet(const u_char *);
void decode_ip(const u_char *, struct nf_v5_body *);
u_int decode_tcp(const u_char *,struct nf_v5_body *);
void package(u_char *conf, const struct pcap_pkthdr *, const u_char *);



/* main */
int main(){
    /* Initiate packet sniffing values/types/structs */
    struct pcap_pkthdr header;      //actual pcap struct
    struct nf_v5_header nfheader;   //netflow header struct
    struct nf_v5_header *p_nfheader; //pointer to header
    struct nf_v5_body nfbody;       //netflow body struct
    struct nf_v5_body *p_nfbody;    //pointer to body
    const u_char *packet;           // pointer to the packet
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *pcap_handle;            //name of packet
    p_nfheader = &nfheader;
    p_nfbody = &nfbody;
    initializeNflowPacket(p_nfbody);
    printNflowPacket(p_nfbody);

    /* Choose sniffing device */
    device = "en0"; //pcap_lookupdev(errbuf);
    if(device == NULL)
      pcap_fatal("pcap_lookupdev", errbuf);
    printf("Sniffing network traffic on device %s \n", device);

    /* Initialize output binding values/types/structs */
    int sockfd;
    unsigned short port = 8000;
    struct sockaddr_in target;  //socket adress struct
    unsigned char buffer[4096];

    /* Establish remote connection */
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))==-1)       //create socket
          printf("**Error, fatal: establishing socket");
    target.sin_family= AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &(target.sin_addr));  //convert to network and assign IP
    memset(&(target.sin_zero), '\0', 8); // Zero the rest of the struct.
    struct configStruct cf = { &sockfd, (u_char *)p_nfbody};


    /* Primary capturing piece */
    pcap_handle=pcap_open_live(device, 4096, 1, 0, errbuf);
    if (pcap_handle == NULL)
        pcap_fatal("pcap_open_live", errbuf);
    pcap_loop(pcap_handle, 20, package, (u_char *)&cf);
    pcap_close(pcap_handle);

};



/* --- Protocol Decoding functions --- */
/* Decode Ethernet */
void decode_ethernet(const u_char *header_start) {
   printf("Successfully decoded ethr_hdr\n");
};

/* Decode IP */
void decode_ip(const u_char *header_start, struct nf_v5_body *nfbody) {
     const struct ip_hdr *ip_header;
     struct nf_v5_body *nf_body;
     // Set local variables
     ip_header = (const struct ip_hdr *)header_start;
     nf_body = (struct nf_v5_body *)nfbody;

     printf("\tDecoding IP layer...\n");
     nf_body->ip_src_address = htonl(ip_header->src); //assign source IP
     nf_body->ip_dst_address = htonl(ip_header->dst); //assign destination IP
     nf_body->dOctets = htonl(ip_header->tl);            // assign bytes of flow
     nf_body->prot = ip_header->prot;             //assign protocol
  };

/* Decode TCP */
u_int decode_tcp(const u_char *header_start,struct nf_v5_body *nfbody) {
     u_int header_size;
     const struct tcp_hdr *tcp_header;
     struct nf_v5_body *nf_body;
     unsigned char flags;

     // Set local variables
     tcp_header = (const struct tcp_hdr *)header_start;
     nf_body = (struct nf_v5_body *)nfbody;
     flags = EMPTY_FLAGS;
     header_size = 4 * tcp_header->off;

     printf("\t\tDecoding TCP layer....\n\n");
     nf_body->sport = htons(tcp_header->sport); //assign source port
     nf_body->dport = htons(tcp_header->dport); //assign destination port

     if(tcp_header->tcp_flags & TCP_FIN)
        flags |= TCP_FIN;
     if(tcp_header->tcp_flags & TCP_SYN)
        flags |= TCP_SYN;
     if(tcp_header->tcp_flags & TCP_RST)
        flags |= TCP_RST;
     if(tcp_header->tcp_flags & TCP_PUSH)
        flags |= TCP_PUSH;
     if(tcp_header->tcp_flags & TCP_ACK)
        flags |= TCP_ACK;
     if(tcp_header->tcp_flags & TCP_URG)
        flags |= TCP_URG;

     nf_body->tcp_flags = flags;    //assign OR of TCP flags

     return header_size;
};

/* Package function -- Repackages pcap stats as netflow stats */

void package(u_char *conf, const struct pcap_pkthdr *cap_header, const u_char *packet){
      int tcp_header_length, total_header_size, pkt_data_len;
      int sendrtrn;
      struct configStruct *c = (struct configStruct *)conf;
      int *fd = c->fd;
      u_char *body =c->pktpntr;
      struct nf_v5_body *nfb = (struct nf_v5_body *)body; //pointer to the global netflow body

      printf("Captured a %d byte packet\n", cap_header->len);
      decode_ethernet(packet);
      decode_ip(packet+ETHER_HDR_LEN, nfb);
      tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr), nfb);
      total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr);
      printNflowPacket(nfb);

      printf("Sending Network Traffic....\n");
      if((sendrtrn = send_nf5_body(*fd, nfb)) == 0)
          printf("Fatal error with send_nf5_body.\n");

};
