#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>

static DES_cblock ivsetup = {0xE1, 0xE2, 0xE3, 0xD4, 0xD5, 0xC6, 0xC7, 0xA8};
static DES_key_schedule key;
 
void generate_key(){
    char* k = "abcdefgh";
    DES_cblock key_b;
    DES_string_to_key (k, &key_b);
    /*if (DES_is_weak_key(&key_b) == 1)
        printf("Weak Key\n");
    else
        printf("Strong Key\n");*/
    DES_set_key((C_Block *)key_b, &key);
}

char *
Encrypt( char *Msg, int size)
{
 
        static char*    Res;
        //int             n=0;
        DES_cblock iv;
        //DES_cblock      Key2;
        //DES_key_schedule schedule;
 
        Res = ( char * ) malloc( size );
 
        memcpy(iv, ivsetup, sizeof(ivsetup));

        /* Prepare the key for use with DES_cfb64_encrypt */
        /*memcpy( Key2, Key,8);
        DES_set_odd_parity( &Key2 );
        DES_set_key_checked( &Key2, &schedule );*/
 
        /* Encryption occurs here */
        DES_ncbc_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
                           size, &key, &iv, DES_ENCRYPT );
 
         return (Res);
}
 
 
char *
Decrypt( char *Msg, int size)
{
 
        static char*    Res;
        //int             n=0;
        DES_cblock iv;
        //DES_cblock      Key2;
        //DES_key_schedule schedule;
 
        Res = ( char * ) malloc( size );
 
        memcpy(iv, ivsetup, sizeof(ivsetup));
 
        /* Prepare the key for use with DES_cfb64_encrypt */
        /*memcpy( Key2, Key,8);
        DES_set_odd_parity( &Key2 );
        DES_set_key_checked( &Key2, &schedule );*/
 
        /* Decryption occurs here */
        DES_ncbc_encrypt( ( unsigned char * ) Msg, ( unsigned char * ) Res,
                           size, &key, &iv, DES_DECRYPT );
 
        return (Res);
 
}


void Replace_Last_Block(char* msg)
{
    int i;

    for(i=32; i<=39; i++)
    {
        msg[i+16] = msg[i];
    }

}


int Search_Byte()
{
    char request[] = "GET / HTTP/1.1\r\n\r\nCookie:sessid=aaaaaaah\r\n\r\nxxxx01234567";
    char *encrypted, *decrypted;
    int len = strlen(request);
    int i, byte;

    encrypted=malloc(sizeof(encrypted) * len);
    decrypted=malloc(sizeof(decrypted) * len);

    printf("%c\n", request[55]);

    for (i = 0; i < 256; ++i)
    {
        printf("%d\n", i);
        request[39] = i;

        memcpy(encrypted,Encrypt(request,len), len);

        Replace_Last_Block(encrypted);

        memcpy(decrypted,Decrypt(encrypted,len), len);

        if (decrypted[55] == '7')
        {
            byte = 7 ^ encrypted[47] ^ encrypted[31];
            return byte;
        }
    }

    return -1;
}


int main() {
 
    //char key[]="password";
    char clear[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=abcdefgh\r\n\r\nxxxx01234567";
    char *decrypted;
    char *encrypted;
    int res;
     
    encrypted=malloc(sizeof(clear));
    decrypted=malloc(sizeof(clear));

    generate_key();

    res = Search_Byte();
    printf("\nbyte = %d\n", res);
     
    /*printf("Clear text\t : %s \n",clear);
    memcpy(encrypted,Encrypt(clear,sizeof(clear)), sizeof(clear));
    printf("Encrypted text\t : %s \n",encrypted);
    memcpy(decrypted,Decrypt(encrypted,sizeof(clear)), sizeof(clear));
    printf("Decrypted text\t : %s \n",decrypted);*/
     

    return (0);
}
