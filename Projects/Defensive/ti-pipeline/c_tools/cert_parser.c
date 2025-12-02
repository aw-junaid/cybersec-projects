/**
 * Certificate Parser for Threat Intelligence Pipeline
 * 
 * Extracts information from SSL/TLS certificates:
 * - Subject and issuer
 * - Subject Alternative Names (SANs)
 * - Fingerprints (SHA256)
 * - Validity period
 * 
 * Compile: gcc -o cert_parser cert_parser.c -lssl -lcrypto -ljansson
 * Usage: ./cert_parser certificate.pem
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <jansson.h>

void extract_cert_info(X509 *cert, json_t *output) {
    // Subject
    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject) {
        char subject_buf[256];
        X509_NAME_oneline(subject, subject_buf, sizeof(subject_buf));
        json_object_set_new(output, "subject", json_string(subject_buf));
        
        // Extract Common Name
        int cn_index = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if (cn_index >= 0) {
            X509_NAME_ENTRY *cn_entry = X509_NAME_get_entry(subject, cn_index);
            ASN1_STRING *cn_data = X509_NAME_ENTRY_get_data(cn_entry);
            if (cn_data) {
                unsigned char *cn_str = NULL;
                int cn_len = ASN1_STRING_to_UTF8(&cn_str, cn_data);
                if (cn_len > 0) {
                    json_object_set_new(output, "common_name", json_string((char*)cn_str));
                    OPENSSL_free(cn_str);
                }
            }
        }
    }

    // Issuer
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer) {
        char issuer_buf[256];
        X509_NAME_oneline(issuer, issuer_buf, sizeof(issuer_buf));
        json_object_set_new(output, "issuer", json_string(issuer_buf));
    }

    // Fingerprint (SHA256)
    unsigned char fingerprint[SHA256_DIGEST_LENGTH];
    if (X509_digest(cert, EVP_sha256(), fingerprint, NULL)) {
        char fp_str[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(fp_str + (i * 2), "%02x", fingerprint[i]);
        }
        fp_str[SHA256_DIGEST_LENGTH * 2] = '\0';
        json_object_set_new(output, "fingerprint_sha256", json_string(fp_str));
    }

    // Validity
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);
    
    if (not_before) {
        char not_before_str[64];
        ASN1_TIME_print((BIO *)not_before_str, not_before);
        json_object_set_new(output, "validity_not_before", json_string(not_before_str));
    }
    
    if (not_after) {
        char not_after_str[64];
        ASN1_TIME_print((BIO *)not_after_str, not_after);
        json_object_set_new(output, "validity_not_after", json_string(not_after_str));
    }

    // Subject Alternative Names
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    san_names = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    
    if (san_names) {
        json_t *sans = json_array();
        int san_count = sk_GENERAL_NAME_num(san_names);
        
        for (int i = 0; i < san_count; i++) {
            GENERAL_NAME *san = sk_GENERAL_NAME_value(san_names, i);
            
            if (san->type == GEN_DNS) {
                unsigned char *dns_name = NULL;
                int dns_len = ASN1_STRING_to_UTF8(&dns_name, san->d.dNSName);
                if (dns_len > 0) {
                    json_array_append_new(sans, json_string((char*)dns_name));
                    OPENSSL_free(dns_name);
                }
            } else if (san->type == GEN_IPADD) {
                char ip_str[INET6_ADDRSTRLEN];
                if (san->d.iPAddress->length == 4) {
                    inet_ntop(AF_INET, san->d.iPAddress->data, ip_str, sizeof(ip_str));
                    json_array_append_new(sans, json_string(ip_str));
                } else if (san->d.iPAddress->length == 16) {
                    inet_ntop(AF_INET6, san->d.iPAddress->data, ip_str, sizeof(ip_str));
                    json_array_append_new(sans, json_string(ip_str));
                }
            }
        }
        
        json_object_set_new(output, "subject_alternative_names", sans);
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }

    // Serial number
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (bn) {
            char *serial_str = BN_bn2hex(bn);
            json_object_set_new(output, "serial_number", json_string(serial_str));
            OPENSSL_free(serial_str);
            BN_free(bn);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <certificate_file>\n", argv[0]);
        return 1;
    }

    FILE *cert_file = fopen(argv[1], "r");
    if (!cert_file) {
        fprintf(stderr, "Error opening certificate file: %s\n", argv[1]);
        return 2;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Read certificate
    X509 *cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);

    if (!cert) {
        fprintf(stderr, "Error reading certificate from file\n");
        return 3;
    }

    // Extract certificate information
    json_t *output = json_object();
    extract_cert_info(cert, output);

    // Print JSON output
    char *output_str = json_dumps(output, JSON_INDENT(2));
    printf("%s\n", output_str);

    // Cleanup
    free(output_str);
    json_decref(output);
    X509_free(cert);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
