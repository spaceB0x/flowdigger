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


/* Netflow v9 packet structure */





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

/* pcap fatal error handler */
void pcap_fatal(const char *failed_in, const char *errbuf){
    printf("Fatal error in %s: %s\n",failed_in, errbuf);
    exit(1);

};
