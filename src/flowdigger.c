/* Flowdigger was written by Tyler Welton 'spaceB0x'
2015 - Issued under the self termed 'Jesus License'
"Freely you have received; freely give" -Matt 10:8
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <regex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "nflow.h"
#include "netmeth.h"
#include "config.h"
#include "rgex.h"

//method declarations
void package(u_char *conf, const struct pcap_pkthdr *, const u_char *);

/* Typedef to be able to pass 2 parameters to the loop callback function */
struct paramPassStruct{
    int *fd;
    u_char *pktpntr;
    u_char *pktpntrhead;
    u_char *pktpntrecombo;
    u_int *extractor;
};


/*#######################*/
      /* main */
/*#######################*/
int main(int argc, char *argv[]){

    /* Initiate configurations*/
    struct config conf= set_config_from_file(config_file_path);
    print_config(&conf);
    /* Initiate packet sniffing values/types/structs */
    struct pcap_pkthdr header;      //actual pcap struct
    struct nf_v5_body nfbody;       //netflow body struct
    struct nf_v5_header nfheader;   //netflow header struct
    struct nf_v5_combo nfcombo;     //netflow combo struct
    struct nf_v5_body *p_nfbody;    //pointer to body
    struct nf_v5_header *p_nfheader; //pointer to header
    struct nf_v5_combo *p_nfcombo;    //pointer to combo struct
    p_nfheader = &nfheader;         /*Initialize netflow pointeers */
    p_nfbody = &nfbody;
    p_nfcombo = &nfcombo;

    /* Initialize various integers*/
    int capsize;
    char errbuf[PCAP_ERRBUF_SIZE];                    // error buffer declarations
    const u_char *packet;                             // pointer to the packet
    pcap_t *pcap_handle;                              // name of packet
    unsigned int tm = getepoch();                     // get the time in epoch
    struct sockaddr_in target;                        //socket adress struct
    unsigned char buffer[4096];
    int sockfd;

    /* Initialize configuration vars */
    char *colip = conf.collector_ip;
    char *device = conf.interface;                    // device to listen on (string)
    unsigned short port = conf.collector_port;
    u_int extractor=conf.digger_enabled;              // binary flag to turn 'digger' on and off

    /* Initialize flow packets */
    initializeNflowPacketHeader(p_nfheader,tm);
    initializeNflowPacketBody(p_nfbody);

    /* Initialize any regex */
    const char * regex_text;                          //regex string
    //regex_t r_ip = "hello";
    const char *xff = "X-Forwarded-For";              //x
    const char *tcip= "True-Client-IP";
    if(conf.proxy_ip != NULL){
      regex_text = conf.proxy_ip;

    } //initialize regular expressions

    /* Choose sniffing device */
    if(device == NULL)
      pcap_fatal("pcap_lookupdev", errbuf);
    printf("Sniffing network traffic on device %s \n", device);

    /* Establish remote connection */
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))==-1)           //create socket
          printf("**Error, fatal: establishing socket\n");
    target.sin_family= AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, colip, &(target.sin_addr));              //convert to network and assign IP
    memset(&(target.sin_zero), '\0', 8);                        // Zero the rest of the struct.
    struct paramPassStruct cf = { &sockfd, (u_char *)p_nfbody, (u_char *)p_nfheader, (u_char *)p_nfcombo, &extractor};
    if(connect(sockfd, (struct sockaddr *)&target, sizeof(struct sockaddr)) == -1)
        printf("**Error, fatal: establishing socket connection.\n");

    /* Primary capturing piece */
    pcap_handle=pcap_open_live(device, 4096, 1, 0, errbuf);
    if (pcap_handle == NULL)
        pcap_fatal("pcap_open_live", errbuf);
    pcap_loop(pcap_handle, -1, package, (u_char *)&cf);
    pcap_close(pcap_handle);

    //printf("Header pointer: %p  and Body pointer: %p \n",p_nfheader, p_nfbody);

};
/* Package function -- Repackages pcap stats as netflow stats */

void package(u_char *conf, const struct pcap_pkthdr *cap_header, const u_char *packet){
      int tcp_header_length, total_header_size, pkt_data_len;
      int sendrtrn, sendrtrnh, sendrtrnb;
      struct paramPassStruct *c = (struct paramPassStruct *)conf;
      int *fd = c->fd;
      u_char *header =c->pktpntrhead;
      u_char *body =c->pktpntr;
      u_char *combo = c->pktpntrecombo;
      u_int *extractor = c->extractor;
      struct nf_v5_header *nfh = (struct nf_v5_header *)header ; //pointer to global netflow header
      struct nf_v5_body *nfb = (struct nf_v5_body *)body; //pointer to the global netflow body
      struct nf_v5_combo *nfc = (struct nf_v5_combo *)combo;


      //printf("Captured a %d byte packet\n", cap_header->len);
      decode_ethernet(packet);
      decode_ip(packet+ETHER_HDR_LEN, nfb);
      tcp_header_length = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr), nfb, extractor);
      total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr);

      //For now always extract body
       //if(*extractor == 1 && (ntohs(nfb->dport) == (short)80 || ntohs(nfb->dport) == (short)443)){
      int datasize = cap_header->len;
      decode_data(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_length, datasize);

      //printNflowPacketHeader(nfh);
      //printNflowPacketBody(nfb);

      /* Sending Packets */
      // Header
      //printf("Sending NetFlow Header...\n");
      //if((sendrtrnh = send_nf5_header(*fd, nfh)) == 0)
      //    printf("Fatal error with send_nf5_header.\n");
      //Body
      //printf("Sending NetFlow Body...\n");
      //if((sendrtrn = send_nf5_body(*fd, nfb)) == 0)
      //    printf("Fatal error with send_nf5_body.\n");

      //printf("Sending both at same time...\n");
      if((sendrtrnb = send_nf5_both(*fd, nfh, nfb, nfc)) == 0)
          printf("Fatal error with send_nf5_both\n");
};
