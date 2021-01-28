#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#include <string>
#include <fstream>
#include <iostream>
#include <iterator>

#include <jsoncpp/json/json.h>

#define FAIL    -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    if ( FAIL == (sd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) ) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    bzero(&addr, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    addr.sin_port = htons(port);

    if ( FAIL == connect(sd, (struct sockaddr*)&addr, sizeof(addr)) )
    {
        perror("connect");
        close(sd);
        exit(EXIT_FAILURE);
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    //method = TLSv1_2_client_method();  /* Create new client-method instance */
    const SSL_METHOD *method = TLS_client_method();  /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No certificates configured.\n");
}


int main(int argc, char **argv)
{
    if ( argc != 7 )
    {
        printf("Usage: %s -h <hostname> -p <portnum> -f <file>\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    std::string serv_ip;
    int16_t port;
    std::string file_name;

    int rez = 0;
    while ( -1 != (rez = getopt(argc,argv,"h:p:f:")) )
    {
        switch (rez)
        {
            case 'h': serv_ip = optarg;
                break;
            case 'p': port = atoi(optarg);
                break;
            case 'f': file_name = optarg;
                break;
//	    case '?':   system handler for this error
        }
    }

    std::ifstream ifs(file_name.data());
    if (!ifs) {
        std::cout << "Open file error: " << file_name << std::endl;
        exit(EXIT_SUCCESS);
    }
    std::string fileData((std::istream_iterator<char>(ifs)), std::istream_iterator<char>());
    ifs.close();

    SSL_CTX *ctx;
    int server;
    SSL *ssl;

    char buf[1024];
    bzero(buf, sizeof(buf));

    SSL_library_init();
    ctx = InitCTX();

    server = OpenConnection(serv_ip.data(), port);

    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */

    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */

        SSL_write(ssl, fileData.data(), fileData.size());   /* encrypt & send message */

        SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */

        std::string str(buf);

        Json::Reader reader;
        Json::Value obj;
        reader.parse(str, obj);

        std::string signature = obj["signature"].asString();

        //
        // TODO verify signature!
        //
        if (signature == signature) {
            Json::StreamWriterBuilder builder;
            std::string outStr = Json::writeString(builder, obj);

            std::ofstream ofs("result.txt");
            if (ofs) {
                ofs << outStr;
                ofs.close();
            }
        }
        else {
            std::ofstream ofs("err.log", std::ofstream::app);
            if (ofs) {
                time_t t;
                time(&t);
                ofs << asctime(localtime(&t));
                ofs.close();
            }
        }

        SSL_free(ssl);        /* release connection state */
    }

    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */

    return 0;
}
