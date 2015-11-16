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


/* main */

int main(){
  /* Initiate packet sniffing values/types/structs */
  struct pcap_pkthdr header;      //actual pcap struct
  struct nf_v5_header nfheader;   //netflow header struct
  struct nf_v5_header *p_nfheader; //pointer to header
  struct nf_v5_body nfbody;       //netflow body struct
  struct nf_v5_body *p_nfbody;    //pointer to body

  p_nfheader = &nfheader;
  p_nfbody = &nfbody;

  const u_char *packet;           // pointer to the packet
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;            //name of packet


  /* Initialize output binding values/types/structs */


  /* Choose sniffing device */
  device = "eth1"; //pcap_lookupdev(errbuf);
  if(device == NULL)
    pcap_fatal("pcap_lookupdev", errbuf);

  printf("Sniffing network traffic on device %s \n", device);

  pcap_handle=pcap_open_live(device, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL){
      pcap_fatal("pcap_open_live", errbuf);
    }

  pcap_loop(pcap_handle, 20, package, ((u_char *)p_nfbody));

  pcap_close(pcap_handle);

};



/* --- Protocol Decoding functions --- */
/* Decode Ethernet */
void decode_ethernet(const u_char *header_start) {
   printf("Successfully decoded ethr_hdr\n");
};

/* Decode IP */
void decode_ip(const u_char *header_start, u_char *nfbody) {
   const struct ip_hdr *ip_header;
   struct nf_v5_body *nf_body;
   // Set local variables
   ip_header = (const struct ip_hdr *)header_start;
   nf_body = (struct nf_v5_body *)nfbody;

   printf("\tDecoding IP layer\n");
   nf_body->ip_src_address = ip_header->src; //assign source IP
   nf_body->ip_dst_address = ip_header->dst; //assign destination IP
   nf_body->dOctets = ip_header->tl;            // assign bytes of flow
   nf_body->prot = ip_header->prot;             //assign protocol
};

/* Decode TCP */
u_int decode_tcp(const u_char *header_start,u_char *nfbody) {
   u_int header_size;
   const struct tcp_hdr *tcp_header;
   unsigned char flags;

   // Set local variables
   tcp_header = (const struct tcp_hdr *)header_start;
   nf_body = (struct nf_v5_body *)nfbody;
   flags = EMPTY_FLAGS;
   header_size = 4 * tcp_header->off;

   printf("\tDecoding TCP....\n");
   nf_body->sport = tcp_header->sport; //assign source port
   nf_body->dport = tcp_header->dport; //assign destination port

   if(tcp_header->tcp_flags & TCP_FIN)
      flags |= TCP_FIN
   if(tcp_header->tcp_flags & TCP_SYN)
      flags |= TCP_SYN
   if(tcp_header->tcp_flags & TCP_RST)
      flags |= TCP_RST
   if(tcp_header->tcp_flags & TCP_PUSH)
      flags |= TCP_PUSH
   if(tcp_header->tcp_flags & TCP_ACK)
      flags |= TCP_ACK
   if(tcp_header->tcp_flags & TCP_URG)
      flags |= TCP_URG

   nf_body->tcp_flags = flags;    //assign OR of TCP flags

   return header_size;
};

/* Package function -- Repackages pcap stats as netflow stats */
int package(u_char *nfbody, const struct pcap_pkthdr *cap_header, const u_char *packet){
    int tcp_header, total_header_size, pkt_data_len;

};
