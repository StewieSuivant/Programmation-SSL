//SSL-Client.c
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl/des.h"
#include "Attack.h"
 
#define FAIL    -1

static DES_cblock ivsetup;
static DES_key_schedule key;

//struct sockaddr_in addr;
 
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
 
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = SSLv3_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");

    //res = SSL_CTX_set_cert_verify_callback(ctx, cert, );
}

// fonction callback à ajouter
int verify_callback (int ok, X509_STORE_CTX *store)
{
  int depth = X509_STORE_CTX_get_error_depth(store);
  X509 *cert = X509_STORE_CTX_get_current_cert(store);
  int err = X509_STORE_CTX_get_error(store);
 
  if(depth > 0) return ok; // just check server certif IP (at depth 0), else preverify "ok" is enough...
 
  printf("+++++ check peer certificate +++++\n");
  printf(" * preverify ok = %d\n", ok); 
  printf(" * chain depth = %d\n", depth); 
  printf(" * error code %i (%s)\n", err, X509_verify_cert_error_string(err));
  char data[256];
  X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
  printf(" * issuer = %s\n", data);
  X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
  printf(" * subject = %s\n", data);
  char * certifip = data+4;
   printf(" * certificate server IP = %s\n", certifip);
  //char * serverip = inet_ntoa(addr.sin_addr);
   char * serverip = "127.0.0.1";
   printf(" * server IP = %s\n", serverip);
   printf("test\n");    

  if (ok) {      
    if(strcmp(certifip,serverip) == 0) { 
      printf("SUCCESS: certificate IP (%s) matches server IP (%s)!\n", certifip, serverip);   
      return 1; // continue verification
    }
    else {
      printf("FAILURE: certificate IP (%s) does not match server IP (%s)!\n", certifip, serverip);   
      return 0; // stop verification
    }
  }
 
  return 0; // stop verification
}
 
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;
    // Problème si le cookie fait moins de 8 octets
    char cookie[] = "GET / HTTP/1.1\r\n\r\nCookie:sessid=password\r\n\r\nxxxxxxxxmmmmmmmmmmmmmmmmmmmm01234567";
    //char cookie[] = "test";
    int len = strlen(cookie);
    char* request = malloc(sizeof(cookie));
    char* encrypted = malloc(sizeof(cookie));
    char * result = malloc(sizeof(char)*9);
    char* decrypted = malloc(sizeof(cookie));
 
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
 
    ctx = InitCTX();
    LoadCertificates(ctx, "Client.crt", "Client.key"); /* load certs */

    // code à ajouter pour vérifier le certificat du serveur...
    SSL_CTX_load_verify_locations (ctx, "ca.crt",0);        
    SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER, verify_callback);

    server = OpenConnection(hostname, atoi(portnum));

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   char *msg = "Hello???";
        char res[9];
 
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */

        //res = SSL_get_verify_result(ssl);
        //printf("res = %ld\n", res);

        SSL_write(ssl, msg, strlen(msg));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	// ***************************************************************
	// ****** Test read-write ssl ********
	//memcpy(request,cookie,len);
	/*memcpy(encrypted,Encrypt_DES(cookie,len), len);	    
	memcpy(decrypted, Decrypt_DES(encrypted,len), len);
	printf("\n\nClient Cookie : '%s'\n", cookie);
	printf("Client Decrypted: '%s'\n", decrypted);
	
	SSL_write(ssl, encrypted, len);
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
	printf("Received: \"%s\"\n", buf);*/
	
	// ******* Test recherche cookie *********
	/*memcpy(request,cookie,len);
	int i;
	for (i = 0; i < 8; ++i)
	  {
	    printf("Octet num : %d\n", i);
	    while(strcmp(buf, "VALIDE") != 0)
	      {
		generate_key();
		memcpy(encrypted,Encrypt_DES(request,len), len);
		Replace_Last_Block(encrypted);
		SSL_write(ssl, encrypted, len);
 
		bytes = SSL_read(ssl, buf, sizeof(buf)); 
		buf[bytes] = 0;
	      }
	    result[7-i] = '7' ^ encrypted[47] ^ encrypted[31];
	    memcpy(request, changeRequest(request), strlen(cookie));
	    memset(buf, 0, 1024);
 
	  }
	result[8] = '\0';
 
	printf("cle = %s\n", res);*/

	// ****** Test recherche octet ******
	char octet;
	while(strcmp(buf, "VALIDE") != 0)
	      {
		// Il faut trouver un moyen d'envoyer la clé de chiffrement au server
		generate_key()
		  
		memcpy(encrypted,Encrypt_DES(cookie,len), len);
		Replace_Last_Block(encrypted);
		SSL_write(ssl, encrypted, len);
		
		bytes = SSL_read(ssl, buf, sizeof(buf)); 
		buf[bytes] = 0;
	      }

	// *************************************************************** 
	
        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
