#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include "Attack.h"

static char * cypherMode;
static char * attackMode;

//static DES_cblock ivsetup;
static DES_key_schedule key;


/************* Chiffrement *************/



void generate_key()
{
    unsigned char k[8];
    DES_cblock key_b;

    RAND_bytes(k, 8);
    DES_string_to_key (k, &key_b);
    DES_set_key((C_Block *)key_b, &key);

    //printf("%x\n", key.ks->cblock);
}

/*void generate_iv(){
  
  unsigned char iv[8];
  RAND_bytes(iv, 8);
  DES_string_to_key (iv, &ivsetup);
}

void generate_IV_Key(){
  void generate_iv();
  void generate_key();
  }*/

char *
Encrypt_DES( char *Msg, int size)
{
  DES_cblock ivsetup;
  //DES_key_schedule key;
  unsigned char k[] = "abcdefgh";
  DES_cblock key_b;
  DES_string_to_key (k, &key_b);
  DES_set_key((C_Block *)key_b, &key);
	
  unsigned char iv[] = "abcdefgh";
  DES_string_to_key (iv, &ivsetup);
 
  char*    Res;
  DES_cblock iv2;
 
  Res = ( char * ) malloc( size );

  memcpy(iv2, ivsetup, sizeof(ivsetup));
 
  /* Encryption occurs here */
  DES_ncbc_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
		    size, &key, &iv2, DES_ENCRYPT );
 
  return (Res);
}
 
 
char *
Decrypt_DES( char *Msg, int size)
{
 
  char*    Res;
  DES_cblock iv2;
  DES_cblock ivsetup;
  //DES_key_schedule key;
	
  unsigned char k[] = "abcdefgh";
  DES_cblock key_b;
  DES_string_to_key (k, &key_b);
  DES_set_key((C_Block *)key_b, &key);
	
  unsigned char iv[] = "abcdefgh";
  DES_string_to_key (iv, &ivsetup);
 
  Res = ( char * ) malloc( size );

  memcpy(iv2, ivsetup, sizeof(ivsetup));
 
  /* Decryption occurs here */
  DES_ncbc_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
		    size, &key, &iv2, DES_DECRYPT );
 
  return (Res);
 
}

/****************** Tools *******************************/

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
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


void Replace_Last_Block(char* msg)
{
    int i;

    for(i=32; i<=39; i++)
    {
        msg[i+16] = msg[i];
    }

}

char * changeRequest(char * request){
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

int Search_Byte_Poodle(char* request)
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

    if (decrypted[55] == '7')
    {
        byte = '7' ^ encrypted[47] ^ encrypted[31];
        //printf("%c\n", (char)byte);
        return byte;
    }

    return -1;
}

/************************* POA *******************************/

int Search_Byte_POA(char* request)
{
    //char request[] = "GET / HTTP/1.1\r\n\r\nCookie:sessid=abcdefgh\r\n\r\nxxxx01234567";
    char *encrypted, *decrypted;
    int len = strlen(request);
    int i, byte;

    encrypted=malloc(sizeof(encrypted) * len);
    decrypted=malloc(sizeof(decrypted) * len);

    if( strcmp(cypherMode, "DES") == 0)
      memcpy(encrypted,Encrypt_DES(request,len), len);

    Replace_Last_Block(encrypted);

    for (i = 0; i < 256; ++i)
    {
        encrypted[47] = i;
	if( strcmp(cypherMode, "DES") == 0)
	  memcpy(decrypted,Decrypt_DES(encrypted,len), len);

        if (decrypted[55] == '7')
        {

            byte = '7' ^ encrypted[47] ^ encrypted[31];
            printf("%c\n", (char)byte);
            return byte;
        }
    }

    return -1;
}

char * attack(char *request){
  char * res = malloc(sizeof(char)*9);
  char result = 0;
  int i = 0;
  
  if(strcmp(attackMode, "POODLE") == 0){
    for (i; i < 8; ++i)
      {
        int j = 0;
        while((result=Search_Byte_Poodle(request)) == -1)
	  {
            j++;
            //generate_key();
	  }
        printf("octet %d : %d tentatives\n", i, j);

        res[7-i] = result;
        memcpy(request, changeRequest(request), strlen(request));
        //printf("%s\n",request);
      }
  }
  else if(strcmp(attackMode, "POODLE") == 0){
    for( i; i < 8; ++i){
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
/*
int main(int argc, char* argv[]) {
    char cookie[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=password\r\n\r\nxxxxxxxxmmmmmmmmmmmmmmmmmmmm01234567";
    char *decrypted;
    char *encrypted;
    char* res;
    char* request = malloc(sizeof(cookie));
    
    if( argc != 3){
      printf("Need two arguments \n");
      return EXIT_FAILURE;
    }
    cypherMode = argv[1];
    attackMode = argv[2];
     
    encrypted=malloc(sizeof(cookie));
    decrypted=malloc(sizeof(cookie));

    generate_IV_Key();
    
    memcpy(request, cookie, strlen(cookie));
    
    res = attack(request);

    printf("\nbyte = %s\n", res);

    return (0);
}
*/
