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

}
