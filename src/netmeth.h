#include <time.h>

/* File of networking methods */
#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define EMPTY_FLAGS 0x00

/* method declarations */
void pcap_fatal(const char *, const char *);
int getepoch();
void decode_ethernet(const u_char *);
void decode_ip(const u_char *, struct nf_v5_body *);
u_int decode_tcp(const u_char *,struct nf_v5_body *,u_int *);
void decode_data(const u_char *, int);


/* Redefinitions of network header structures (because I'm dumb and the real ones make my brain hurt)*/
/* Ethernet Header */
struct ether_hdr{
  unsigned char ether_dest_addr[ETHER_ADDR_LEN];
  unsigned char ether_src_addr[ETHER_ADDR_LEN];
  unsigned short ether_type;
};

/* IP header */
struct ip_hdr{
    unsigned char ip_version_and_header_length;
    unsigned char tos;                         // Type of service
    unsigned short tl;                         // Total length
    unsigned short id;                         // Identification
    unsigned short off;                        // Fragmentation offset field
    unsigned char ttl;                         // Time to Live
    unsigned char prot;                        // Protocol
    unsigned short checksum;                   // Checksum
    unsigned int src;                          // IP source address
    unsigned int dst;                          // IP destination address
};

/* TCP header */
struct tcp_hdr{
    unsigned short sport;                     // Source port
    unsigned short dport;                     // Destination port
    unsigned int seq;                         // Sequence Number
    unsigned int ack;                         // Acknowledgement number
    unsigned char unused1:4;                  // 4 bits from the 6 bits of reserved space. Unused
    unsigned char off:4;                      // Data offset field (for little endian)
    unsigned char tcp_flags;                  // TCP Flags and 2 bits from reserved space.
  #define TCP_FIN 0x01
  #define TCP_SYN 0x02
  #define TCP_RST 0x04                       /* TCP FLAGS */
  #define TCP_PUSH 0x08
  #define TCP_ACK 0x10
  #define TCP_URG 0x20
    unsigned short win;                       // Window
    unsigned short sum;                       // Checksum
    unsigned short urp;                       // Urgent pointer

};


/* pcap fatal error handler */
void pcap_fatal(const char *failed_in, const char *errbuf){
    printf("Fatal error in %s: %s\n",failed_in, errbuf);
    exit(1);
};

/* Method to dump raw pcap data (Stolen from Jon Erikson). Used for testing */
void dump(const unsigned char *data_buffer, const unsigned int length) {
     unsigned char byte;
     unsigned int i, j;
     for(i=0; i < length; i++) {
        byte = data_buffer[i];
        printf("%02x ", data_buffer[i]);  // Display byte in hex.
        if(((i%16)==15) || (i==length-1)) {
           for(j=0; j < 15-(i%16); j++)
              printf("   ");
           printf("| ");
           for(j=(i-(i%16)); j <= i; j++) {  // Display printable bytes from line.
              byte = data_buffer[j];
              if((byte > 31) && (byte < 127)) // Outside printable char range
                 printf("%c", byte);
              else
                 printf(".");
           }
           printf("\n"); // End of the dump line (each line is 16 bytes)
        } // End if
     } // End for
};

int getepoch(){
  return (int)time(NULL);
}

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
u_int decode_tcp(const u_char *header_start,struct nf_v5_body *nfbody, u_int *extractor) {
     u_int header_size;
     const struct tcp_hdr *tcp_header;
     struct nf_v5_body *nf_body;
     unsigned char flags;

     // Set local variables
     tcp_header = (const struct tcp_hdr *)header_start;
     nf_body = (struct nf_v5_body *)nfbody;
     flags = EMPTY_FLAGS;
     header_size = 4 * tcp_header->off;
     printf("\t\tDecoding TCP layer....\n");
     nf_body->sport = htons(tcp_header->sport); //assign source port
     nf_body->dport = htons(tcp_header->dport); //assign destination port

     //bitwise OR all TCP flags together
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

void decode_data(const u_char *header_start, int size){
    char *xstring = "X-Forwarded-For:" ;
    char *string;

    printf("\t\t\tDecoding data payload....\n");
    int bytes_to_read, read_bytes;
    read_bytes=0;
    bytes_to_read = size;
    char data[size];
    printf("bytes to read: %d", bytes_to_read);
    while(bytes_to_read > 0){

        data[read_bytes] = *header_start;
        read_bytes -=1;
        header_start+=1;
        bytes_to_read -= 1;

    }
    printf("\n");
};
