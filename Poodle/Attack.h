#ifndef ATTACK_H
#define ATTACK_H


DES_cblock ivsetup;
DES_key_schedule key;

// genearate Random IV and Key 
void generate_key(unsigned char *k);
void generate_iv(unsigned char *iv);
void generate_IV_Key(unsigned char *iv, unsigned char *k);

/* DES function */
char *Encrypt_DES( char *Msg, int size); 
char *Decryp_DES( char *Msg, int size);

void hex_print(const void* pv, size_t len);
/* Change the last block to key block */
void Replace_Last_Block(char* msg);
/* Shift the message */
char * changeRequest(char * request);
/* Search the last byte of the key block */
int Search_Byte_Poodle(char* request);
int Search_Byte_POA(char* request);
char* attack(char *request);

#endif

