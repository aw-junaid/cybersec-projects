/**
 * Signature Checker for Honeynet
 * Verifies node registrations and signed artifacts
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <jansson.h>

void initialize_openssl() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

EVP_PKEY *load_public_key(const char *cert_path) {
    FILE *fp = fopen(cert_path, "r");
    if (!fp) {
        fprintf(stderr, "Error opening certificate file: %s\n", cert_path);
        return NULL;
    }
    
    X509 *x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!x509) {
        fprintf(stderr, "Error reading X509 certificate\n");
        return NULL;
    }
    
    EVP_PKEY *pkey = X509_get_pubkey(x509);
    X509_free(x509);
    
    return pkey;
}

int verify_signature(const char *data, size_t data_len, 
                    const unsigned char *signature, size_t sig_len,
                    EVP_PKEY *pkey) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    
    if (EVP_VerifyInit(ctx, EVP_sha256()) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (EVP_VerifyUpdate(ctx, data, data_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    int result = EVP_VerifyFinal(ctx, signature, sig_len, pkey);
    EVP_MD_CTX_free(ctx);
    
    return (result == 1);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cert_file> <data_file> <signature_file>\n", argv[0]);
        fprintf(stderr, "Safety: For lab use only. Verifies node signatures.\n");
        return 2;
    }
    
    initialize_openssl();
    
    // Load public key
    EVP_PKEY *pkey = load_public_key(argv[1]);
    if (!pkey) {
        fprintf(stderr, "Failed to load public key\n");
        return 1;
    }
    
    // Read data file
    FILE *data_fp = fopen(argv[2], "rb");
    if (!data_fp) {
        fprintf(stderr, "Error opening data file: %s\n", argv[2]);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    fseek(data_fp, 0, SEEK_END);
    long data_len = ftell(data_fp);
    fseek(data_fp, 0, SEEK_SET);
    
    char *data = malloc(data_len);
    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(data_fp);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    fread(data, 1, data_len, data_fp);
    fclose(data_fp);
    
    // Read signature file
    FILE *sig_fp = fopen(argv[3], "rb");
    if (!sig_fp) {
        fprintf(stderr, "Error opening signature file: %s\n", argv[3]);
        free(data);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    fseek(sig_fp, 0, SEEK_END);
    long sig_len = ftell(sig_fp);
    fseek(sig_fp, 0, SEEK_SET);
    
    unsigned char *signature = malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(sig_fp);
        free(data);
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    fread(signature, 1, sig_len, sig_fp);
    fclose(sig_fp);
    
    // Verify signature
    int verified = verify_signature(data, data_len, signature, sig_len, pkey);
    
    // Create JSON output
    json_t *result = json_object();
    json_object_set_new(result, "verified", json_boolean(verified));
    json_object_set_new(result, "data_file", json_string(argv[2]));
    json_object_set_new(result, "certificate", json_string(argv[1]));
    
    char *output = json_dumps(result, JSON_INDENT(2));
    printf("%s\n", output);
    
    free(output);
    json_decref(result);
    free(data);
    free(signature);
    EVP_PKEY_free(pkey);
    
    return verified ? 0 : 1;
}
