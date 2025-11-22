#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define TIMEOUT 10

typedef struct {
    char *host;
    int port;
    SSL_CTX *ctx;
} tls_test_t;

void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_ssl_context(int ssl_version) {
    SSL_CTX *ctx;
    
    switch(ssl_version) {
        case 1:
            ctx = SSL_CTX_new(SSLv23_method());
            break;
        case 2:
            ctx = SSL_CTX_new(TLSv1_2_method());
            break;
        case 3:
            ctx = SSL_CTX_new(TLSv1_1_method());
            break;
        case 4:
            ctx = SSL_CTX_new(TLSv1_method());
            break;
        default:
            ctx = SSL_CTX_new(SSLv23_method());
    }
    
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    
    return ctx;
}

int test_tls_connection(tls_test_t *test, int ssl_version, const char *version_name) {
    int sockfd;
    struct hostent *host;
    struct sockaddr_in addr;
    SSL *ssl;
    
    printf("[*] Testing %s... ", version_name);
    
    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return -1;
    }
    
    // Get host info
    if ((host = gethostbyname(test->host)) == NULL) {
        herror("gethostbyname");
        close(sockfd);
        return -1;
    }
    
    // Set up address
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(test->port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    
    // Connect with timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }
    
    // Create SSL connection
    test->ctx = create_ssl_context(ssl_version);
    if (!test->ctx) {
        close(sockfd);
        return -1;
    }
    
    ssl = SSL_new(test->ctx);
    SSL_set_fd(ssl, sockfd);
    
    if (SSL_connect(ssl) <= 0) {
        printf("FAILED\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("SUCCESS\n");
        printf("    Protocol: %s\n", SSL_get_version(ssl));
        printf("    Cipher: %s\n", SSL_get_cipher(ssl));
        
        // Check certificate
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            X509_NAME *subject = X509_get_subject_name(cert);
            X509_NAME *issuer = X509_get_issuer_name(cert);
            
            char subj_buf[256];
            char iss_buf[256];
            
            X509_NAME_oneline(subject, subj_buf, sizeof(subj_buf));
            X509_NAME_oneline(issuer, iss_buf, sizeof(iss_buf));
            
            printf("    Subject: %s\n", subj_buf);
            printf("    Issuer: %s\n", iss_buf);
            
            X509_free(cert);
        }
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(test->ctx);
    
    return 0;
}

void test_downgrade_attack(tls_test_t *test) {
    printf("\n[*] Testing TLS downgrade vulnerability...\n");
    
    // Test from strongest to weakest
    struct {
        int version;
        const char *name;
    } versions[] = {
        {2, "TLS 1.2"},
        {3, "TLS 1.1"},
        {4, "TLS 1.0"},
        {1, "SSL 2.0/3.0"},
        {0, NULL}
    };
    
    int supported_versions = 0;
    int weak_versions = 0;
    
    for (int i = 0; versions[i].name != NULL; i++) {
        if (test_tls_connection(test, versions[i].version, versions[i].name) == 0) {
            supported_versions++;
            if (i >= 2) { // TLS 1.0 and below are weak
                weak_versions++;
            }
        }
    }
    
    if (weak_versions > 0) {
        printf("\n[!] VULNERABLE: Server supports weak/deprecated protocols\n");
        printf("    Risk: TLS downgrade attacks possible\n");
    } else {
        printf("\n[+] SECURE: No weak protocols supported\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <host> <port>\n", argv[0]);
        printf("Example: %s example.com 443\n");
        return 1;
    }
    
    tls_test_t test;
    test.host = argv[1];
    test.port = atoi(argv[2]);
    
    printf("TLS Downgrade & MITM Tester\n");
    printf("Target: %s:%d\n\n", test.host, test.port);
    
    initialize_openssl();
    
    test_downgrade_attack(&test);
    
    cleanup_openssl();
    
    return 0;
}
