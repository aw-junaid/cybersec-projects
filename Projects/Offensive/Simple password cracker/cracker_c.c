/* cracker_c.c - simple educational password cracker (dictionary + brute-force)
   
   AUTHORIZED USE ONLY: For educational purposes and authorized testing only.
   
   Compile:
     gcc -o cracker_c cracker_c.c -lcrypto
     
   Usage examples:
     # Dictionary attack on MD5 hash
     ./cracker_c dict md5 5d41402abc4b2a76b9719d911017c592 wordlist.txt
     
     # Brute-force SHA256 hash with lowercase letters, length 1-4
     ./cracker_c brute sha256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 abcdefghijklmnopqrstuvwxyz 1 4
     
     # Brute-force numeric PIN (0-9), length 4
     ./cracker_c brute md5 5d41402abc4b2a76b9719d911017c592 0123456789 4 4
   
   Notes:
     - Supports md5, sha1, sha256 via OpenSSL
     - Single target hash only (modify for multiple hashes)
     - Brute-force complexity grows exponentially with length and charset size
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <ctype.h>

/**
 * Convert hexadecimal string to binary data
 * 
 * @param hex: Input hex string (e.g., "5d41402a")
 * @param out: Output buffer for binary data
 * @param outlen: Length of output buffer in bytes
 */
void hex2bin(const char *hex, unsigned char *out, size_t outlen) {
    size_t i;
    for (i = 0; i < outlen; ++i) {
        unsigned int v;
        // Read 2 hex characters at a time and convert to byte
        sscanf(hex + 2*i, "%2x", &v);
        out[i] = (unsigned char)v;
    }
}

/**
 * Hash a buffer using specified algorithm
 * 
 * @param algo: Hash algorithm name ("md5", "sha1", "sha256")
 * @param buf: Input data to hash
 * @param buflen: Length of input data
 * @param out: Output buffer for hash result
 * @param outlen: Pointer to store output hash length
 */
void hash_buf(const char *algo, const unsigned char *buf, size_t buflen, 
              unsigned char *out, unsigned int *outlen) {
    const EVP_MD *md = NULL;
    
    // Select hash algorithm
    if (strcmp(algo, "md5") == 0) 
        md = EVP_md5();
    else if (strcmp(algo, "sha1") == 0) 
        md = EVP_sha1();
    else if (strcmp(algo, "sha256") == 0) 
        md = EVP_sha256();
    else { 
        fprintf(stderr, "Unsupported algorithm: %s\n", algo); 
        exit(1); 
    }
    
    // Create and initialize hash context
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, buf, buflen);
    EVP_DigestFinal_ex(ctx, out, outlen);
    EVP_MD_CTX_free(ctx);
}

/**
 * Print binary data as hexadecimal string
 * 
 * @param buf: Binary data to print
 * @param len: Length of data in bytes
 */
void hexprint(const unsigned char *buf, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) 
        printf("%02x", buf[i]);
    printf("\n");
}

/**
 * Perform dictionary attack using a wordlist
 * 
 * @param algo: Hash algorithm name
 * @param target_hex: Target hash as hex string
 * @param wordlist: Path to wordlist file
 * @return: 1 if password found, 0 if not found
 */
int dict_mode(const char *algo, const char *target_hex, const char *wordlist) {
    FILE *f = fopen(wordlist, "r");
    if (!f) { 
        perror("Failed to open wordlist"); 
        return 0; 
    }
    
    // Convert target hex string to binary for comparison
    unsigned char target_bin[EVP_MAX_MD_SIZE];
    size_t target_len_bytes = strlen(target_hex) / 2;
    hex2bin(target_hex, target_bin, target_len_bytes);
    
    char line[1024];
    int line_count = 0;
    
    printf("[*] Starting dictionary attack...\n");
    
    // Read wordlist line by line
    while (fgets(line, sizeof(line), f)) {
        size_t line_length = strlen(line);
        
        // Remove newline/carriage return characters
        if (line_length && (line[line_length - 1] == '\n' || line[line_length - 1] == '\r')) 
            line[--line_length] = 0;
        
        // Skip empty lines
        if (line_length == 0) 
            continue;
        
        // Hash the current candidate password
        unsigned int hash_length = 0;
        unsigned char hash_result[EVP_MAX_MD_SIZE];
        hash_buf(algo, (unsigned char*)line, line_length, hash_result, &hash_length);
        
        // Compare with target hash
        if (hash_length == target_len_bytes && 
            memcmp(hash_result, target_bin, hash_length) == 0) {
            printf("[FOUND] %s -> '%s' (dictionary attack)\n", target_hex, line);
            fclose(f);
            return 1;
        }
        
        line_count++;
        // Progress indicator every 10000 lines
        if (line_count % 10000 == 0) {
            printf("[*] Processed %d words...\n", line_count);
        }
    }
    
    fclose(f);
    printf("[*] Dictionary attack completed. %d words tested.\n", line_count);
    return 0;
}

/**
 * Perform brute-force attack by generating all possible combinations
 * 
 * @param algo: Hash algorithm name
 * @param target_hex: Target hash as hex string
 * @param charset: Character set to use for brute-force
 * @param min_len: Minimum password length
 * @param max_len: Maximum password length
 * @return: 1 if password found, 0 if not found
 */
int brute_mode(const char *algo, const char *target_hex, const char *charset, 
               int min_len, int max_len) {
    // Convert target hex string to binary for comparison
    unsigned char target_bin[EVP_MAX_MD_SIZE];
    size_t target_len_bytes = strlen(target_hex) / 2;
    hex2bin(target_hex, target_bin, target_len_bytes);
    
    size_t charset_length = strlen(charset);
    if (charset_length == 0) { 
        fprintf(stderr, "Empty character set\n"); 
        return 0; 
    }
    
    printf("[*] Starting brute-force: charset size=%zu, lengths %d-%d\n", 
           charset_length, min_len, max_len);
    
    // Safety warning for high complexity
    if (max_len > 6 && charset_length > 10) {
        printf("[!] WARNING: High complexity attack - this may take very long!\n");
        printf("[!] Total combinations: up to ~%.0f\n", 
               pow(charset_length, max_len) - pow(charset_length, min_len - 1));
    }
    
    // Iterate through each password length
    for (int current_length = min_len; current_length <= max_len; ++current_length) {
        printf("[+] Trying length %d (%.0f combinations)\n", 
               current_length, pow(charset_length, current_length));
        
        // Allocate and initialize index array (like an odometer)
        int *indices = calloc(current_length, sizeof(int));
        if (!indices) {
            fprintf(stderr, "Memory allocation failed\n");
            return 0;
        }
        
        long combinations_tested = 0;
        
        // Generate all combinations for current length
        while (1) {
            // Build candidate string from current indices
            char *candidate = malloc(current_length + 1);
            for (int i = 0; i < current_length; i++) {
                candidate[i] = charset[indices[i]];
            }
            candidate[current_length] = '\0';  // Null-terminate
            
            // Hash the candidate
            unsigned char hash_result[EVP_MAX_MD_SIZE];
            unsigned int hash_length = 0;
            hash_buf(algo, (unsigned char*)candidate, current_length, hash_result, &hash_length);
            
            // Compare with target
            if (hash_length == target_len_bytes && 
                memcmp(hash_result, target_bin, hash_length) == 0) {
                printf("[FOUND] %s -> '%s' (brute-force, length=%d)\n", 
                       target_hex, candidate, current_length);
                free(candidate);
                free(indices);
                return 1;
            }
            
            free(candidate);
            combinations_tested++;
            
            // Progress indicator for large searches
            if (combinations_tested % 1000000 == 0) {
                printf("[*] Tested %ld combinations at length %d...\n", 
                       combinations_tested, current_length);
            }
            
            // Increment indices (like an odometer)
            int position = 0;
            while (position < current_length) {
                indices[position]++;
                if ((size_t)indices[position] < charset_length) 
                    break;  // No carry-over needed
                indices[position] = 0;  // Reset current position
                position++;             // Carry over to next position
            }
            
            // If we carried over beyond the last position, we're done
            if (position == current_length) 
                break;
        }
        
        printf("[*] Completed length %d (%ld combinations tested)\n", 
               current_length, combinations_tested);
        free(indices);
    }
    
    return 0;
}

/**
 * Main function - parse arguments and dispatch to appropriate mode
 */
int main(int argc, char **argv) {
    // Display usage if insufficient arguments
    if (argc < 5) {
        fprintf(stderr, 
            "Educational Password Cracker - AUTHORIZED USE ONLY\n\n"
            "Usage:\n"
            "  Dictionary attack:\n"
            "    %s dict <md5|sha1|sha256> <target_hex> <wordlist_file>\n\n"
            "  Brute-force attack:\n"
            "    %s brute <md5|sha1|sha256> <target_hex> <charset> <min_len> <max_len>\n\n"
            "Examples:\n"
            "  %s dict md5 5d41402abc4b2a76b9719d911017c592 wordlist.txt\n"
            "  %s brute sha1 aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d abcdefgh 1 4\n"
            "  %s brute md5 5d41402abc4b2a76b9719d911017c592 0123456789 4 4\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }
    
    const char *mode = argv[1];
    const char *algorithm = argv[2];
    const char *target_hash = argv[3];
    
    printf("[*] Starting cracker: mode=%s, algorithm=%s, target=%s\n", 
           mode, algorithm, target_hash);
    
    // Dispatch to dictionary or brute-force mode
    if (strcmp(mode, "dict") == 0) {
        if (argc < 5) {
            fprintf(stderr, "Dictionary mode requires wordlist file\n");
            return 1;
        }
        const char *wordlist_file = argv[4];
        int found = dict_mode(algorithm, target_hash, wordlist_file);
        if (!found) 
            printf("[-] Password not found in wordlist\n");
        
    } else if (strcmp(mode, "brute") == 0) {
        if (argc < 7) { 
            fprintf(stderr, "Brute-force mode requires charset, min_len, and max_len\n");
            return 1; 
        }
        const char *charset = argv[4];
        int min_length = atoi(argv[5]);
        int max_length = atoi(argv[6]);
        
        // Validate length parameters
        if (min_length <= 0 || max_length <= 0 || min_length > max_length) {
            fprintf(stderr, "Invalid length parameters: min=%d, max=%d\n", 
                    min_length, max_length);
            return 1;
        }
        
        int found = brute_mode(algorithm, target_hash, charset, min_length, max_length);
        if (!found) 
            printf("[-] Password not found via brute-force\n");
            
    } else {
        fprintf(stderr, "Unknown mode: %s (use 'dict' or 'brute')\n", mode);
        return 1;
    }
    
    return 0;
}
