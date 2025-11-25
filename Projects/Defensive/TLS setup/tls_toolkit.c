/**
 * TLS Setup & Hardening Guide - C Implementation
 * Compile: gcc -o tls_toolkit tls_toolkit.c -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <time.h>

#define MAX_BUFFER 4096

typedef struct {
    char* name;
    char* protocols;
    char* ciphers;
    char* curves;
    int security_level;
} TLSConfig;

typedef struct {
    char* hostname;
    int port;
    char* tls_version;
    char* cipher;
    char* certificate_info;
    int vulnerabilities;
} TLSTestResult;

void initialize_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

TLSConfig* create_tls_config(const char* level) {
    TLSConfig* config = malloc(sizeof(TLSConfig));
    
    if(strcmp(level, "modern") == 0) {
        config->name = "Modern";
        config->protocols = "TLSv1.3 TLSv1.2";
        config->ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        config->curves = "X25519:secp521r1:secp384r1";
        config->security_level = 3;
    } else if(strcmp(level, "intermediate") == 0) {
        config->name = "Intermediate";
        config->protocols = "TLSv1.2 TLSv1.3";
        config->ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
        config->curves = "prime256v1:secp384r1:secp521r1";
        config->security_level = 2;
    } else {
        config->name = "Compatible";
        config->protocols = "TLSv1.2 TLSv1.3";
        config->ciphers = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256";
        config->curves = "prime256v1:secp384r1:secp521r1";
        config->security_level = 1;
    }
    
    return config;
}

void generate_nginx_config(TLSConfig* config, const char* output_file) {
    FILE* fp = output_file ? fopen(output_file, "w") : stdout;
    
    if(!fp) {
        printf("Error: Cannot open output file\n");
        return;
    }
    
    fprintf(fp, "# TLS Hardening Configuration for Nginx\n");
    fprintf(fp, "# Security Level: %s\n", config->name);
    fprintf(fp, "# Generated: %s\n", __DATE__);
    fprintf(fp, "\n");
    
    fprintf(fp, "ssl_protocols %s;\n", config->protocols);
    fprintf(fp, "ssl_ciphers %s;\n", config->ciphers);
    fprintf(fp, "ssl_prefer_server_ciphers on;\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# Modern SSL settings\n");
    fprintf(fp, "ssl_session_timeout 1d;\n");
    fprintf(fp, "ssl_session_cache shared:SSL:50m;\n");
    fprintf(fp, "ssl_session_tickets off;\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# Security headers\n");
    fprintf(fp, "add_header Strict-Transport-Security \"max-age=63072000\" always;\n");
    fprintf(fp, "add_header X-Frame-Options DENY;\n");
    fprintf(fp, "add_header X-Content-Type-Options nosniff;\n");
    fprintf(fp, "add_header X-XSS-Protection \"1; mode=block\";\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# DH parameters\n");
    fprintf(fp, "ssl_dhparam /etc/nginx/dhparam.pem;\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# OCSP Stapling\n");
    fprintf(fp, "ssl_stapling on;\n");
    fprintf(fp, "ssl_stapling_verify on;\n");
    fprintf(fp, "resolver 8.8.8.8 8.8.4.4 valid=300s;\n");
    fprintf(fp, "resolver_timeout 5s;\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# ECDH curves\n");
    fprintf(fp, "ssl_ecdh_curve %s;\n", config->curves);
    
    if(output_file) {
        fclose(fp);
        printf("[+] Nginx configuration saved to: %s\n", output_file);
    }
}

void generate_apache_config(TLSConfig* config, const char* output_file) {
    FILE* fp = output_file ? fopen(output_file, "w") : stdout;
    
    if(!fp) {
        printf("Error: Cannot open output file\n");
        return;
    }
    
    fprintf(fp, "# TLS Hardening Configuration for Apache\n");
    fprintf(fp, "# Security Level: %s\n", config->name);
    fprintf(fp, "# Generated: %s\n", __DATE__);
    fprintf(fp, "\n");
    
    fprintf(fp, "SSLProtocol %s\n", config->protocols);
    fprintf(fp, "SSLCipherSuite %s\n", config->ciphers);
    fprintf(fp, "SSLHonorCipherOrder on\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# Modern SSL settings\n");
    fprintf(fp, "SSLSessionCache \"shmcb:/var/run/ssl_scache(512000)\"\n");
    fprintf(fp, "SSLSessionCacheTimeout 300\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# Security headers\n");
    fprintf(fp, "Header always set Strict-Transport-Security \"max-age=63072000\"\n");
    fprintf(fp, "Header always set X-Frame-Options DENY\n");
    fprintf(fp, "Header always set X-Content-Type-Options nosniff\n");
    fprintf(fp, "Header always set X-XSS-Protection \"1; mode=block\"\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "# OCSP Stapling\n");
    fprintf(fp, "SSLUseStapling On\n");
    fprintf(fp, "SSLStaplingResponderTimeout 5\n");
    fprintf(fp, "SSLStaplingReturnResponderErrors Off\n");
    fprintf(fp, "SSLStaplingCache \"shmcb:/var/run/ocsp(128000)\"\n");
    
    if(output_file) {
        fclose(fp);
        printf("[+] Apache configuration saved to: %s\n", output_file);
    }
}

void test_tls_connection(const char* hostname, int port) {
    printf("[*] Testing TLS connection to %s:%d\n", hostname, port);
    
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) {
        printf("Error: Cannot create SSL context\n");
        return;
    }
    
    // Set minimum TLS version
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    BIO* bio = BIO_new_ssl_connect(ctx);
    if(!bio) {
        printf("Error: Cannot create BIO\n");
        SSL_CTX_free(ctx);
        return;
    }
    
    SSL* ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    // Set SNI
    SSL_set_tlsext_host_name(ssl, hostname);
    
    char hostport[256];
    snprintf(hostport, sizeof(hostport), "%s:%d", hostname, port);
    BIO_set_conn_hostname(bio, hostport);
    
    if(BIO_do_connect(bio) <= 0) {
        printf("Error: Cannot connect to %s\n", hostport);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return;
    }
    
    if(BIO_do_handshake(bio) <= 0) {
        printf("Error: TLS handshake failed\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return;
    }
    
    printf("[+] TLS connection established\n");
    
    // Get connection information
    printf("TLS Version: %s\n", SSL_get_version(ssl));
    
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    printf("Cipher Suite: %s\n", SSL_CIPHER_get_name(cipher));
    
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) {
        printf("Certificate Subject: ");
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
        printf("\n");
        
        printf("Certificate Issuer: ");
        X509_NAME_print_ex_fp(stdout, X509_get_issuer_name(cert), 0, XN_FLAG_ONELINE);
        printf("\n");
        
        // Check certificate expiration
        ASN1_TIME* not_after = X509_get_notAfter(cert);
        printf("Certificate Expires: ");
        ASN1_TIME_print_fp(stdout, not_after);
        printf("\n");
        
        X509_free(cert);
    }
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
}

void print_usage() {
    printf("TLS Setup & Hardening Toolkit\n");
    printf("Usage:\n");
    printf("  Generate Nginx config:  tls_toolkit nginx <level> [output_file]\n");
    printf("  Generate Apache config: tls_toolkit apache <level> [output_file]\n");
    printf("  Test TLS connection:    tls_toolkit test <hostname> [port]\n");
    printf("\n");
    printf("Security levels: modern, intermediate, compatible\n");
    printf("Default port: 443\n");
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        print_usage();
        return 1;
    }
    
    initialize_openssl();
    
    if(strcmp(argv[1], "nginx") == 0 && argc >= 3) {
        TLSConfig* config = create_tls_config(argv[2]);
        generate_nginx_config(config, argc > 3 ? argv[3] : NULL);
        free(config);
    }
    else if(strcmp(argv[1], "apache") == 0 && argc >= 3) {
        TLSConfig* config = create_tls_config(argv[2]);
        generate_apache_config(config, argc > 3 ? argv[3] : NULL);
        free(config);
    }
    else if(strcmp(argv[1], "test") == 0 && argc >= 3) {
        int port = 443;
        if(argc > 3) {
            port = atoi(argv[3]);
        }
        test_tls_connection(argv[2], port);
    }
    else {
        print_usage();
    }
    
    cleanup_openssl();
    return 0;
}
