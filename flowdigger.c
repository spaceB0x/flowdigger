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


/* main */

int main(){
  /* Initiate packet sniffing values/types/structs */
  struct pcap_pkthdr header;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *device;
  pcap_t *pcap_handle;
  int x;

  /* Initialize output binding values/types/structs */


  /* Choose sniffing device */
  device = "eth1"; //pcap_lookupdev(errbuf);
  if(device == NULL)
    pcap_fatal("pcap_lookupdev", errbuf);

  printf("Sniffing network traffic on device %s \n", device);

  pcap_handle=pcap_open_live(device, 4096, 0, 0, errbuf);

  /* Start sniffing */
  for (x=0; x < 3; x++){
    packet = pcap_next(pcap_handle, &header);
    printf("Received a %d byte packet\n", header.len);
    dump(packet,header.len);
  }
  pcap_close(pcap_handle);

}
