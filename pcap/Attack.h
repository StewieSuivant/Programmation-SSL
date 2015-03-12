#ifndef ATTACK_H
#define ATTACK_H


// genearate Random IV and Key 
void generate_key();
/*
void generate_iv();
void generate_IV_Key();*/
/* DES function */
char *Encrypt_DES( char *Msg, int size); 
char *Decryp_DES( char *Msg, int size);

/* Change the last block to key block */
void Replace_Last_Block(char* msg);
/* Shift the message */
char * changeRequest(char * request);
/* Search the last byte of the key block */
int Search_Byte_Poodle(char* request);
int Search_Byte_POA(char* request);
char* attack(char *request);
  
#endif

