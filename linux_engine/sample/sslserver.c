#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#define LISTENQ 5
#define BUFSIZE 1024
#define PORT 5000
const char *buf1="HTTP/1.1 200 OK\n\
Content-Type:text/html\n\n\
<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n\
<HTML>\n\
<HEAD>\n\
<TITLE>Caium networks</TITLE>\n\
<META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=iso-8859-1\">\n\
</HEAD>\n\
<BODY>\n\
<PRE>\n\
<par><h4>Sample Application Using Octeon Engine</h3></par><par>Server default page.</par>\n\
</PRE>\n\
</BODY>\n\
</HTML>\n";

int main(int argc, char *argv[])
{
   int listenfd, connfd, len, port = PORT;
   struct sockaddr_in servaddr, clieaddr;
   char buf[BUFSIZE + 1];
   SSL_METHOD *meth;
   SSL_CTX *ctx;
   SSL *ssl;
   BIO *sbio;
   ENGINE *e = NULL;

   argc--;
   argv++;
   while (argc >= 1) {
		if (strcmp(*argv, "-port") == 0) {
			if (--argc < 1) goto usage_help;
			port = atoi(*(++argv));
		}
		else
			goto usage_help;
   		argc--;
		argv++;
   }
   if (port == PORT)
	printf ("Default port 5000 enabled, if you want to change use -port option\n");

   SSL_library_init();
   SSL_load_error_strings();

#ifndef DONT_USE_OCTEON_ENGINE
   /* Make ALL ENGINE implementations bundled with OpenSSL available */
   ENGINE_load_builtin_engines();
   /* Loading the engine dynamically */
      e = ENGINE_by_id("dynamic");
      if(e) {
           if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", "octeon", 0) || 
               !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
                       ENGINE_free(e);
                       exit (-1);
           }

           if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
                   printf("Unable to initialise the Engine\n");
                   exit (-1);
           }
   }
#endif

   meth = (SSL_METHOD *)SSLv23_server_method();
   if ((ctx = SSL_CTX_new(meth)) == NULL) {
      printf("creation of SSL_CTX object failed\n");
      exit(-1);
   }

   SSL_CTX_use_certificate_file(ctx, "sercert1024.pem", SSL_FILETYPE_PEM);
   SSL_CTX_use_PrivateKey_file(ctx, "server1024", SSL_FILETYPE_PEM);
   SSL_CTX_check_private_key(ctx);

   listenfd = socket(AF_INET, SOCK_STREAM, 0);
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr = htons(INADDR_ANY);
   servaddr.sin_port = htons(port);
   bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
   listen(listenfd, LISTENQ);
   len = sizeof(clieaddr);
   if ((connfd = accept(listenfd, (struct sockaddr *) &clieaddr, (socklen_t *)&len)) < 0) {
      printf("accept error\n");
      exit(-1);
   }

   ssl = SSL_new(ctx);
   sbio = BIO_new_socket(connfd, BIO_NOCLOSE);
   SSL_set_bio(ssl, sbio, sbio);
   if (SSL_accept(ssl) <= 0) {
      printf("ssl server accept error\n");
      exit(-1);
   }

   memset(buf, 0, sizeof buf);
   while ((len = SSL_read(ssl, buf, BUFSIZE)) > 0) {
	if (strncmp(buf, "GET / HTTP/", 11) == 0) {
		SSL_write(ssl, buf1, strlen(buf1));
		goto sending_over;
	}
	else {
		printf("Recv msg is : %s\n", buf);
		buf[len] = '\n';
		SSL_write(ssl, buf, len+1);
		memset(buf, 0, sizeof buf);
	}
		
   }
    
sending_over:
#ifndef DONT_USE_OCTEON_ENGINE
   ENGINE_free(e);
#endif
   SSL_shutdown(ssl);
   SSL_free(ssl);
   close(listenfd);
   close(connfd);
   SSL_CTX_free(ctx);

   return 0;

usage_help:
   printf("usage: sslserver [arg]\n");
   printf("  -port arg   - port to accept on (default is %d)\n",PORT);
   printf("\n");
   exit(-1);
}
