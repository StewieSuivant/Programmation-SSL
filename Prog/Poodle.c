#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>

static DES_cblock ivsetup = {0xE1, 0xE2, 0xE3, 0xD4, 0xD5, 0xC6, 0xC7, 0xA8};
static DES_key_schedule key;


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


void generate_key()
{
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
        DES_cblock iv;
 
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
        DES_cblock iv;
 
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

char* changeRequest(char * request){

    int len = strlen(request);
    int i = 0;

    char * newRequest = malloc(sizeof(char) * len);

    for (i; i < 5; ++i)
    {
        newRequest[i] = request[i];
    }
    newRequest[5] = 'a';
    i = 5;
    while(request[i] != 'h'){
        newRequest[i+1] = request[i];
        ++i;
    }
    newRequest[i+1] = request[i];
    i+=2;
    for (i; i < len; ++i)
    {
        newRequest[i] = request[i];
    }

    return newRequest;
}

int Search_Byte(char* request)
{
    //char request[] = "GET / HTTP/1.1\r\n\r\nCookie:sessid=abcdefgh\r\n\r\nxxxx01234567";
    char *encrypted, *decrypted;
    int len = strlen(request);
    int i, byte;

    encrypted=malloc(sizeof(encrypted) * len);
    decrypted=malloc(sizeof(decrypted) * len);

    memcpy(encrypted,Encrypt(request,len), len);

    Replace_Last_Block(encrypted);

    for (i = 0; i < 256; ++i)
    {
        encrypted[47] = i;

        memcpy(decrypted,Decrypt(encrypted,len), len);

        if (decrypted[55] == '7')
        {

            byte = '7' ^ encrypted[47] ^ encrypted[31];
            printf("%c\n", (char)byte);
            return byte;
        }
    }

    return -1;
}


int main() {
    char cookie[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=ajdukfyh\r\n\r\nxxxx01234567";
    char *decrypted;
    char *encrypted;
    //int res;
    char res[9];
    char* request;
     
    encrypted=malloc(sizeof(cookie));
    decrypted=malloc(sizeof(cookie));

    generate_key();

    /*hex_print(cookie, 56);
    memcpy(encrypted,Encrypt(cookie,sizeof(cookie)), sizeof(cookie));
    hex_print(encrypted, 56);
    memcpy(decrypted,Decrypt(encrypted,sizeof(cookie)), sizeof(cookie));
    hex_print(decrypted, 56);*/
    int i = 0;
    memcpy(request, cookie, strlen(cookie));
    for (i; i < 8; ++i)
    {
        res[7-i] = Search_Byte(request);
        memcpy(request, changeRequest(request), strlen(cookie));
        printf("%s\n",request);
    }
    res[8] = '\0';
    printf("\nbyte = %s\n", res);
     
    return (0);
}
