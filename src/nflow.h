/* This header Library was written by Tyler Welton 'spaceB0x'
2015 - Issued under the self termed 'Jesus License'
"Freely you have received; freely give" -Matt 10:8
*/

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>


/* Netflow v5 packet structure */

struct nf_v5_header{
    unsigned short version;             /* Version */
    unsigned short count;               /* Number of flows exported in this packet */
    unsigned int sys_uptime;            /* Current time in milliseconds since the export device booted */
    unsigned int unix_secs;             /* Current count of seconds since 0000 UTC 1970 */
    unsigned int unix_nsecs;            /* Residual nanoseconds since 0000 UTC 1970 */
    unsigned int flow_sequence;         /* Sequence counter of total flows seen */
    unsigned char engine_type;          /* Type of flow-switching engine */
    unsigned char engine_id;            /* Slot number of the flow switching engine */
    unsigned short sampling_interval;   /* First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval */

};

struct nf_v5_body{
    unsigned int ip_src_address;          /* Source IP */
    unsigned int ip_dst_address;          /* Destination IP */
    unsigned int next_hop_ip;             /* IP address of next hop */
    unsigned short in_snmp;               /* Index of input interface */
    unsigned short out_snmp;              /* Index of output interface */
    unsigned int dPkts;                   /* Number of packets in the flow */
    unsigned int dOctets;                 /* Total number of Layer 3 bytes in the packets of the flow */
    unsigned int first;                   /* SysUptime at start of flow */
    unsigned int last;                    /* SysUptime at the time the last packet of the flow was received */
    unsigned short sport;                 /* TCP/UDP source port number */
    unsigned short dport;                 /* TCP/UDP destination port number */
    unsigned char pad1;                   /* unused (zero) bytes */
    unsigned char tcp_flags;               /* Cumulative OR of TCP flags */
    unsigned char prot;                   /* IP protocol type (for example, TCP = 6; UDP = 17) */
    unsigned char tos;                    /* IP type of service (ToS) */
    unsigned short src_as;                /* Autonomous system number of the source, either origin or peer */
    unsigned short dst_as;                /* Autonomous system number of the destination, either origin or peer */
    unsigned char src_mask;               /* Source address prefix mask bits */
    unsigned char dst_mask;               /* Destination address prefix mask bits */
    unsigned short pad2;                  /* Unused (zero) bytes */
};

struct nf_v5_combo{
    struct nf_v5_header header;
    struct nf_v5_body body;
};

/* Netflow v9 packet structure */
        //Coming soon

/* ---------- Transport functions ---------- */


/* Send netflow 5 header.*/
int send_nf5_header(int fd, struct nf_v5_header *header){
    int sent_bytes, bytes_to_send;
    bytes_to_send = sizeof(header);
    while(bytes_to_send > 0){
        sent_bytes= send(fd, header, bytes_to_send, 0);
        if(sent_bytes == -1)
          return 0;                         //returns 0 on error
        bytes_to_send -= sent_bytes;
    }
    return 1;                               //return 1 on success
};


/* Send netflow 5 body */
int send_nf5_body(int fd, struct nf_v5_body *body){
    int sent_bytes, bytes_to_send;
    bytes_to_send = sizeof(body);
    while(bytes_to_send > 0){
        sent_bytes= send(fd, body, bytes_to_send, 0);
        if(sent_bytes == -1)
          return 0;                         //returns 0 on error
        bytes_to_send -= sent_bytes;
    }
    return 1;                               //return 1 on success
};

int send_nf5_both(int fd, struct nf_v5_header *header, struct nf_v5_body *body, struct nf_v5_combo *combo){
    int sent_bytes, bytes_to_send;

    bytes_to_send = sizeof(struct nf_v5_combo);
    while(bytes_to_send > 0){
        sent_bytes= send(fd, header, bytes_to_send, 0);
        if(sent_bytes == -1)
          return 0;                         //returns 0 on error
        bytes_to_send -= sent_bytes;
    }
    return 1;                               //return 1 on success
};

void initializeNflowPacketHeader(struct nf_v5_header *nfpacketh, unsigned int t){
      memset(nfpacketh, '\0', sizeof(struct nf_v5_header));
      nfpacketh->version = htons(5);
      nfpacketh->count = htons(1);
      nfpacketh->unix_secs = htonl(t);
      nfpacketh->flow_sequence = htonl(1);
      nfpacketh->engine_id= 186;
};

void initializeNflowPacketBody(struct nf_v5_body *nfpacket){
      memset(nfpacket, '\0', sizeof(struct nf_v5_body));
      nfpacket->dPkts = htonl(1);
      nfpacket->dOctets = htonl(60);
};

void printNflowPacketHeader(struct nf_v5_header *nfpacket){
      printf("\t\t*** version: %d \n",ntohs(nfpacket->version));
      printf("\t\t*** count: %d \n",ntohs(nfpacket->count));
      printf("\t\t*** sys_uptime: %d \n",nfpacket->sys_uptime);
      printf("\t\t*** unix_secs: %d \n",ntohl(nfpacket->unix_secs));
      printf("\t\t*** unix_nsecs: %d \n",nfpacket->unix_nsecs);
      printf("\t\t*** flow_sequence: %d \n",nfpacket->flow_sequence);
      printf("\t\t*** engine_type: %d \n",nfpacket->engine_type);
      printf("\t\t*** engine_id: %d \n",nfpacket->engine_id);
      printf("\t\t*** sampling_interval: %d \n",nfpacket->sampling_interval);
};
void printNflowPacketBody(struct nf_v5_body *nfpacket){
      printf("\t\t*** ip_src_address: %d \n",ntohl(nfpacket->ip_src_address));
      printf("\t\t*** ip_dst_address: %d\n",ntohl(nfpacket->ip_dst_address));
      printf("\t\t*** next_hop_ip:%d \n",nfpacket->next_hop_ip);
      printf("\t\t*** in_snmp:%d \n",nfpacket->in_snmp);
      printf("\t\t*** out_snmp:%d \n",nfpacket->out_snmp);
      printf("\t\t*** dPkts:%d \n",nfpacket->dPkts);
      printf("\t\t*** dOctets:%d \n",ntohl(nfpacket->dOctets));
      printf("\t\t*** first:%d \n",nfpacket->first);
      printf("\t\t*** last:%d \n",nfpacket->last);
      printf("\t\t*** sport:%d \n",ntohs(nfpacket->sport));
      printf("\t\t*** dport:%d \n",ntohs(nfpacket->dport));
      printf("\t\t*** pad1:%d \n",nfpacket->pad1);
      printf("\t\t*** tcp_flags:%d \n",nfpacket->tcp_flags);
      printf("\t\t*** prot:%d \n",nfpacket->prot);
      printf("\t\t*** tos:%d \n",nfpacket->tos);
      printf("\t\t*** src_as:%d \n",nfpacket->src_as);
      printf("\t\t*** dst_as:%d \n",nfpacket->dst_as);
      printf("\t\t*** src_mask:%d \n",nfpacket->src_mask);
      printf("\t\t*** dst_mask:%d \n",nfpacket->dst_mask);
      printf("\t\t*** pad2:%d \n",nfpacket->pad2);
};

void printHelpMenu(){
  printf("\t*******************************\n");
  printf("\tFlowdigger Help\n\n");
  printf("\tParameters:\n");
  printf("\t\t-a <ip address>          ipaddress of target collector-required\n");
  printf("\t\t-i <network interface>   interface from which to collect traffic-required\n");
  printf("\t\t-p <port>                port of target collector (where flowdata is sent)-required\n");
  printf("\t\t-d                       flag that turns on Header extraction or 'digging'\n\n");
  printf("\tExample Usage:\n");
  printf("\t\t./flowdigger -a 10.0.0.1 -p 8080 -i eth0 -d\n");
};
