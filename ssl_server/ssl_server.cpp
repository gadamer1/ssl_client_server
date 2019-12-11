#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <pthread.h> //for multithread
#define FAIL    -1
/* global variable*/
pthread_mutex_t mutx;
SSL *client[10];
int client_num =0;
bool option =false;


// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = (SSL_METHOD*)TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
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
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void *Servlet(void *argument) /* Serve the connection -- threadable */
{
	SSL *ssl = *(SSL **)argument;
	while (true) {
		const static int BUFSIZE = 1024;
		char buf[BUFSIZE];
		if(SSL_accept(ssl)==FAIL){
			printf("SSL fail\n");
            break;
		}
		ssize_t received = SSL_read(ssl, buf, BUFSIZE - 1);
		if (received == 0 || received == -1) {
			perror("recv failed");
			break;
		}
		buf[received] = '\0';
		if(option){
            pthread_mutex_lock(&mutx);
            /* 클라이언트 수 만큼 같은 메시지를 전달한다 */
            for(int i=0; i<client_num; i++){
                ssize_t sent = SSL_write(client[i], buf, strlen(buf));
                if (sent == 0) {
                    perror("send failed");
                    break;
                }
            }
            pthread_mutex_unlock(&mutx);
        }else{
            ssize_t sent = SSL_write(ssl,buf,strlen(buf));
            if(sent==0){
                perror("send failed");
                break;
            }
        }
		printf("%s\n", buf);
        ShowCerts(ssl);        /* get any certificates */
    }

	pthread_mutex_lock(&mutx);
	for(int i=0; i<client_num; i++){
		if(ssl == client[i]){
			for( ; i<client_num-1; i++)
				client[i] = client[i+1];
			break;
		}
	}
	client_num--;
	pthread_mutex_unlock(&mutx);
}
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;
	pthread_t pthread;

//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 && count !=3 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    if(count==3){
        option =true; // -b option 
    }
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int clientfd = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, clientfd);      /* set connection socket to SSL state */
		pthread_mutex_lock(&mutx);
		client[client_num++] = ssl;
		pthread_mutex_unlock(&mutx);
		pthread_create(&pthread,NULL,Servlet,(void *)&ssl);     /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}