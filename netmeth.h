
/* File of networking methods */

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

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
  #define TCP_RST 0x04                        /* TCP FLAGS */
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


/* Method to dump raw pcap data (Stolen from Jon Erikson) */
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
