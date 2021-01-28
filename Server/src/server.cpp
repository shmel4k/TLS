#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <string>
#include <algorithm>
#include <jsoncpp/json/json.h>

#define FAIL    -1

// Create the SSL socket and initialize the socket address structure
int OpenListener(int port)
{
    int sd;
    if ( FAIL == (sd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) ) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    bzero(&addr, sizeof(struct sockaddr_in));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if ( FAIL == bind(sd, (struct sockaddr*)&addr, sizeof(addr)) )
    {
        perror("can't bind port");
        exit(EXIT_FAILURE);
    }

    if ( FAIL == listen(sd, 10) )
    {
        perror("listen");
        exit(EXIT_FAILURE);
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
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    const SSL_METHOD *method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile)
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
        printf("Client certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        X509_free(cert);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}


void processConn(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024];
    bzero(buf, sizeof(buf));

    int sd;

    if ( SSL_accept(ssl) < 1 ) { /* do SSL-protocol accept */
        //SSL_get_error(ssl, ret);
        ERR_print_errors_fp(stderr);
    }

    else
    {
        ShowCerts(ssl);        /* get any certificates */

        SSL_read(ssl, buf, sizeof(buf)); /* get request */

        std::string str(buf);

        Json::Reader reader;
        Json::Value obj;
        reader.parse(str, obj);

        std::string operation = obj["operation"].asString();

        std::vector<int> data;
        for (Json::Value::iterator iter = obj["numbers"].begin(); iter != obj["numbers"].end(); iter++)
            data.push_back(stoi((*iter).asString()));

        int status = 0;
        float result = 0;
        std::string signature;

        if (!data.empty()) {
            if (operation == "min") {
                result = *std::min_element(data.begin(), data.end());
            }
            else if (operation == "max") {
                result = *std::max_element(data.begin(), data.end());
            }
            else if (operation == "avg") {
                for(auto x : data) {
                    result += x;
                }
                result /= data.size();
            }
            else if (operation == "median") {
                size_t n = data.size();
                if (n & 0x1) {
                    size_t pos = n >> 1;
                    std::nth_element (data.begin(), data.begin()+pos, data.end());
                    result = *(data.begin()+pos);
                }
                else {
                    size_t pos2 = n >> 1;
                    size_t pos = pos2 - 1;
                    std::nth_element (data.begin(), data.begin()+pos, data.end());
                    int val = *(data.begin()+pos);
                    std::nth_element (data.begin(), data.begin()+pos2, data.end());
                    val += *(data.begin()+pos2);
                    result = (float)val / 2;
                }
            }
            else {
                status = 1;
            }
        }
        else {
            status = 1;
        }

        //
        // TODO fill in signature!
        // signature =
        //

        Json::Value outObj;
        outObj["status"] = status;
        outObj["result"] = result;
        outObj["signature"] = signature;

        Json::StreamWriterBuilder builder;
        builder["indentation"] = ""; // If you want whitespace-less output
        std::string outStr = Json::writeString(builder, outObj);

        SSL_write(ssl, outStr.data(), outStr.size()); /* send reply */

    }

    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}


int main(int argc, char **argv)
{
    if ( argc != 2 )
    {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(EXIT_SUCCESS);
    }


    int server;
    char *portnum;
    
    //Only root user have the permission to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!\n");
        exit(EXIT_SUCCESS);
    }

    // Initialize the SSL library
    SSL_library_init();
    SSL_CTX *ctx = InitServerCTX();        /* initialize SSL */

    const char certFile[] = "servOut.pem";
    const char keyFile[] = "servKey.pem";
    LoadCertificates(ctx, certFile, keyFile); /* load certs */

    portnum = argv[1];
    server = OpenListener(atoi(portnum));    /* create server socket */

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

        processConn(ssl);         /* service connection */
    }

    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}
