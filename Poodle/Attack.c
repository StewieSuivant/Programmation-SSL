#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include "Attack.h"

char * cypherMode;
char * attackMode;

//DES_cblock ivsetup;
//DES_key_schedule key;


/************* Chiffrement *************/

void 
generate_key(unsigned char *k)
{
  DES_cblock key_b;

  DES_string_to_key (k, &key_b);
  DES_set_key((C_Block *)key_b, &key);
}

void 
generate_iv(unsigned char *iv)
{
  DES_string_to_key (iv, &ivsetup);
}

void 
generate_IV_Key(unsigned char *iv, unsigned char *k){
  generate_iv(iv);
  generate_key(k);
}

char *
Encrypt_DES(char *Msg, int size)
{
  char *Res;
  DES_cblock iv2;
 
  Res = (char *)malloc(size);

  memcpy(iv2, ivsetup, sizeof(ivsetup));
 
  /* Encryption occurs here */
  DES_ncbc_encrypt((unsigned char *)Msg, (unsigned char *)Res, size, &key, &iv2, DES_ENCRYPT);
 
  return (Res);
}
 
 
char *
Decrypt_DES(char *Msg, int size)
{
 
  char*    Res;
  DES_cblock iv2;
 
  Res = (char *)malloc(size);

  memcpy(iv2, ivsetup, sizeof(ivsetup));
 
  /* Decryption occurs here */
  DES_ncbc_encrypt((unsigned char *)Msg, (unsigned char *)Res, size, &key, &iv2, DES_DECRYPT);
 
  return (Res);
 
}

/****************** Tools *******************************/

void 
hex_print(const void* pv, size_t len)
{
  const unsigned char * p = (const unsigned char*)pv;
  if (NULL == pv)
    printf("NULL");
  else
    {
      size_t i = 0;
      for (; i<len;++i)
	printf("%02X ", *p++);
    }
  printf("\n");
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

char * 
changeRequest(char * request){
  int len = strlen(request);
  int i = 0;
 
  char * newRequest = malloc(sizeof(char) * len);
 
  for(i ; request[i] != '/' ; i++)
    newRequest[i] = request[i];
 
  newRequest[i] = request[i];
  i++;
 
  newRequest[i] = 'A';
 
  for(i ; request[i] != '='; i++)
    newRequest[i+1] = request[i];
  int j = 0;
  for(j; j <= 8; ++j)
    newRequest[i+j+1] = request[i+j];
 
  i+=j+1;
  for(i; i < len ; ++i)
    newRequest[i] = request[i];
 
  return newRequest;
} 

/*********************** Poodle **********************/

int 
Search_Byte_Poodle(char* request)
{
  char *encrypted, *decrypted;
  int len = strlen(request);
  int i, byte;

  encrypted=malloc(sizeof(encrypted) * len);
  decrypted=malloc(sizeof(decrypted) * len);

  if( strcmp(cypherMode, "DES") == 0)
    memcpy(encrypted,Encrypt_DES(request,len), len);

  Replace_Last_Block(encrypted);

  if( strcmp(cypherMode, "DES") == 0)
    memcpy(decrypted,Decrypt_DES(encrypted,len), len);

  if(decrypted[55] == '7')
    {
      byte = '7' ^ encrypted[47] ^ encrypted[31];
      printf("%c\n", (char)byte);
      return byte;
    }

  return -1;
}

/************************* POA *******************************/

int 
Search_Byte_POA(char* request)
{
  char *encrypted, *decrypted;
  int len = strlen(request);
  int i, byte;

  encrypted=malloc(sizeof(encrypted) * len);
  decrypted=malloc(sizeof(decrypted) * len);

  if(strcmp(cypherMode, "DES") == 0)
    memcpy(encrypted,Encrypt_DES(request,len), len);

  Replace_Last_Block(encrypted);

  for (i = 0; i < 256; ++i)
    {
      encrypted[47] = i;
      if(strcmp(cypherMode, "DES") == 0)
	memcpy(decrypted,Decrypt_DES(encrypted,len), len);

      if(decrypted[55] == '7')
        {
	  byte = '7' ^ encrypted[47] ^ encrypted[31];
	  printf("%c\n", (char)byte);
	  return byte;
        }
    }

  return -1;
}

char * 
attack(char *request){
  char * res = malloc(sizeof(char)*9);
  char result = 0;
  int i = 0;
  
  if(strcmp(attackMode, "POODLE") == 0){
    for (i = 0; i < 8; ++i)
      {
	unsigned char k[8];
        int j = 1;
        while((result=Search_Byte_Poodle(request)) == -1)
	  {
            j++;
	    RAND_bytes(k, 8);
            generate_key(k);
	  }
        printf("octet %d : %d tentatives\n", 8-i, j);

        res[7-i] = result;
        memcpy(request, changeRequest(request), strlen(request));
      }
  }
  else if(strcmp(attackMode, "POA") == 0){
    for(i = 0; i < 8; ++i){
      res[7-i] = Search_Byte_POA(request);
      memcpy(request, changeRequest(request), strlen(request));
    }
  }
  else{
    printf("Attack doesn't exist\n");
    exit(EXIT_FAILURE);
  }
  res[8] = '\0';
  return res;
}

/**********************
********* Main ********
**********************/
/*int 
main(int argc, char* argv[]) {
  unsigned char k[8], iv[8];
  char cookie[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=password\r\n\r\nxxxxxxxxmmmmmmmmmmmmmmmmmmmm01234567";
  char *decrypted, *encrypted, *request;
  char* res;
    
  if( argc != 3){
    printf("Need two arguments \n");
    return EXIT_FAILURE;
  }
  cypherMode = argv[1];
  attackMode = argv[2];
     
  encrypted = malloc(sizeof(cookie));
  decrypted = malloc(sizeof(cookie));
  request = malloc(sizeof(cookie));

  RAND_bytes(iv, 8);
  RAND_bytes(k, 8);
  generate_IV_Key(iv,k);
    
  memcpy(request, cookie, strlen(cookie));
    
  res = attack(request);

  printf("\nbyte = %s\n", res);

  return (0);
  }*/
