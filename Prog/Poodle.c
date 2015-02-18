#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/rand.h>

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


/*void generate_key()
{
    char* k = "abcdefgh";
    DES_cblock key_b;
    DES_string_to_key (k, &key_b);
    if (DES_is_weak_key(&key_b) == 1)
        printf("Weak Key\n");
    else
        printf("Strong Key\n");
    DES_set_key((C_Block *)key_b, &key);
}*/


void generate_key()
{
    unsigned char k[8];
    DES_cblock key_b;

    RAND_bytes(k, 8);
    DES_string_to_key (k, &key_b);
    DES_set_key((C_Block *)key_b, &key);

    //printf("%x\n", key.ks->cblock);
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

int Search_Byte(char* request)
{
    char *encrypted, *decrypted;
    int len = strlen(request);
    int i, byte;

    encrypted=malloc(sizeof(encrypted) * len);
    decrypted=malloc(sizeof(decrypted) * len);

    memcpy(encrypted,Encrypt(request,len), len);

    Replace_Last_Block(encrypted);

    memcpy(decrypted,Decrypt(encrypted,len), len);

    if (decrypted[55] == '7')
    {
        byte = '7' ^ encrypted[47] ^ encrypted[31];
        //printf("%c\n", (char)byte);
        return byte;
    }

    return -1;
}


int main() {
    char cookie[]="GET / HTTP/1.1\r\n\r\nCookie:sessid=password\r\n\r\nxxxxxxxxmmmmmmmmmmmmmmmmmmmm01234567";
    char *decrypted;
    char *encrypted;
    //int res;
    char res[9];
    char* request;
    char result = 0;
     
    encrypted=malloc(sizeof(cookie));
    decrypted=malloc(sizeof(cookie));

    generate_key();

    int i = 0;
    memcpy(request, cookie, strlen(cookie));
    for (i; i < 8; ++i)
    {
        char j = 0;
        while((result=Search_Byte(request)) == -1)
        {
            j++;
            generate_key();
        }
        printf("octet %d : %d tentatives\n", i, j);

        res[7-i] = result;
        memcpy(request, changeRequest(request), strlen(cookie));
        printf("%s\n",request);
    }
    res[8] = '\0';
    printf("\nbyte = %s\n", res);

    return (0);
}
