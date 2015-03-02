//SSL-Server.c

#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include<arpa/inet.h>
#include<unistd.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/des.h"
#include "Attack.h"
 
#define FAIL    -1
#define BUFSIZE 1024
 
int main(int argc , char *argv[])
{
  int socket_desc , sock , c , read_size;
  struct sockaddr_in bob, oscar;
  char buf[BUFSIZE];
  unsigned char k[8], iv[8];
  char cookie[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=password\r\n\r\nxxxxxxxxmmmmmmmmmmmmmmmmmmmm01234567";
  int len = strlen(cookie);
  char *decrypted;
     
  //Create socket
  socket_desc = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_desc == -1)
    {
      printf("Could not create socket");
    }
  puts("Socket created");
     
  //Prepare the sockaddr_in structure
  bob.sin_family = AF_INET;
  bob.sin_addr.s_addr = INADDR_ANY;
  bob.sin_port = htons( 8888 );
     
  //Bind
  if( bind(socket_desc,(struct sockaddr *)&bob , sizeof(bob)) < 0)
    {
      //print the error message
      perror("bind failed. Error");
      return 1;
    }
  puts("bind done");
     
  //Listen
  listen(socket_desc , 3);
     
  //Accept and incoming connection
  puts("Waiting for incoming connections...");
  c = sizeof(struct sockaddr_in);
     
  //accept connection from an incoming oscar
  sock = accept(socket_desc, (struct sockaddr *)&oscar, (socklen_t*)&c);
  if (sock < 0)
    {
      perror("accept failed");
      return 1;
    }
  puts("Connection accepted");


  //*****************  POODLE  ***********************
  int i = 0;

  decrypted = malloc(sizeof(cookie));

  // Receive iv
  if((read_size = recv(sock , buf , BUFSIZE , 0)) < 0 )
    {
      perror("recv failed");
    }
  else
    {
      buf[read_size] = '\0';
      generate_iv(buf);
    }
  write(sock, buf, strlen(buf));


  for(i = 0; i < 8; ++i)
    {
      char res = 0;
      while(res != '7')
	{
	  
	  // Receive k
	  printf("\nreceived k...\n");
	  if((read_size = recv(sock , buf , BUFSIZE , 0)) < 0 )
	    {
	      perror("recv failed");
	    }
	  else
	    {
	      buf[read_size] = '\0';
	      generate_key(buf);
	    }
	  
	  printf("send k...\n");
	  
	  printf("k = %s\n", buf);
	  write(sock, buf, 14);

	  
	  printf("received encrypted...\n");
	  if((read_size = recv(sock, buf, BUFSIZE, 0)) < 0 )
	    {
	      perror("recv failed");
	    }
	  else
	    {
	      buf[read_size] = '\0';

	      memcpy(decrypted,Decrypt_DES(buf,len), len);

	      printf("send result...\n");
	      if((res = decrypted[55]) == '7')
		{
		  write(sock, "VALIDE", 6);
		}
	      else
		{
		  write(sock, "INVALIDE", 8);
		}
	    }
	}
    }


  //***************************************************

  sleep(2);
  close(sock);
  return 0;
}
