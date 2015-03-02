//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/des.h"
#include "Attack.h"
 
#define FAIL    -1
#define BUFSIZE 1024

/*
    C ECHO client example using sockets
*/
 
int main(int argc , char *argv[])
{
  int sock;
  struct sockaddr_in oscar;
  char buf[BUFSIZE];
  unsigned char k[8], iv[8];
  char cookie[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=password\r\n\r\nxxxxxxxxmmmmmmmmmmmmmmmmmmmm01234567";
  int len = strlen(cookie);
  char *encrypted, *request;
  char* res = malloc(sizeof(char)*9);
  int read_size = -1;
     
  //Create socket
  sock = socket(AF_INET , SOCK_STREAM , 0);
  if (sock == -1)
    {
      printf("Could not create socket");
    }
  puts("Socket created");
     
  oscar.sin_addr.s_addr = inet_addr("127.0.0.1");
  oscar.sin_family = AF_INET;
  oscar.sin_port = htons( 4444 );
 
  //Connect to remote oscar
  if (connect(sock , (struct sockaddr *)&oscar , sizeof(oscar)) < 0)
    {
      perror("connect failed. Error");
      return 1;
    }
     
  puts("Connected\n");


  //*****************  POODLE  ***********************
   int i = 0;
  char byte = 0;
     
  encrypted = malloc(sizeof(cookie));
  request = malloc(sizeof(cookie));

  RAND_bytes(iv, 8);
  generate_iv(iv);
    
  memcpy(request, cookie, strlen(cookie));

  // Send iv
  if(send(sock, iv, strlen(iv), 0) < 0)
    {
      puts("Send failed");
      return 1;
    }
  if((read_size = recv(sock, buf, BUFSIZE, 0)) < 0)
    {
      puts("recv failed");
    }
  else
    buf[read_size] = '\0';

  for(i = 0; i < 8; ++i)
    {
      memset(buf,0,BUFSIZE);
      while(strcmp(buf,"VALIDE") != 0)
	{
      
	  RAND_bytes(k, 8);
	  generate_key(k);

	  // Send k
	  printf("\nsend k...\n");
	  if(send(sock, k, 14, 0) < 0)
	    {
	      puts("Send failed");
	      return 1;
	    }
	  printf("received k...\n");
	  if((read_size = recv(sock, buf, BUFSIZE, 0)) < 0)
	    {
	      puts("recv failed");
	    }
	  else
	    buf[read_size] = '\0';
  
	  memcpy(encrypted,Encrypt_DES(request,len), len);

	  printf("send encrypted ...\n");
	  if(send(sock, encrypted, len, 0) < 0)
	    {
	      puts("Send failed");
	      return 1;
	    }

	  printf("received result ...\n");
	  if((read_size = recv(sock, buf, BUFSIZE, 0)) < 0)
	    {
	      puts("recv failed");
	    }
	  buf[read_size] = '\0';

	}
      memcpy(request, changeRequest(request), strlen(request));

    }

  //***************************************************
     
  close(sock);
  return 0;
}
