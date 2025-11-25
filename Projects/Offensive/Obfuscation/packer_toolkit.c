/**
 * Obfuscation & Packer Research Toolkit - C Implementation
 * Compile: gcc -o packer_toolkit packer_toolkit.c -lz -llzma -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zlib.h>
#include <lzma.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_BUFFER_SIZE 1024*1024  // 1MB
#define ENTROPY_THRESHOLD 7.0

typedef struct {
    uint8_t *data;
    size_t size;
} buffer_t;

typedef struct {
    char name[9];
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t characteristics;
    double entropy;
} pe_section_t;

// Simple XOR obfuscation
void xor_obfuscate(uint8_t *data, size_t size, uint8_t key) {
    for(size_t i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Calculate Shannon entropy
double calculate_entropy(uint8_t *data, size_t size) {
    if(size == 0) return 0.0;
    
    int frequency[256] = {0};
    double entropy = 0.0;
    
    // Calculate byte frequencies
    for(size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }
    
    // Calculate entropy
    for(int i = 0; i < 256; i++) {
        if(frequency[i] > 0) {
            double probability = (double)frequency[i] / size;
            entropy -= probability * (__builtin_popcount(frequency[i]) - 1);
        }
    }
    
    return entropy;
}

// Compress using zlib
buffer_t compress_zlib(uint8_t *data, size_t size) {
    buffer_t result = {NULL, 0};
    uLongf compressed_size = compressBound(size);
    result.data = malloc(compressed_size);
    
    if(compress(result.data, &compressed_size, data, size) == Z_OK) {
        result.size = compressed_size;
    } else {
        free(result.data);
        result.data = NULL;
    }
    
    return result;
}

// Compress using LZMA
buffer_t compress_lzma(uint8_t *data, size_t size) {
    buffer_t result = {NULL, 0};
    size_t compressed_size = size * 2; // Conservative estimate
    result.data = malloc(compressed_size);
    
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_easy_encoder(&strm, 6, LZMA_CHECK_CRC64);
    
    if(ret == LZMA_OK) {
        strm.next_in = data;
        strm.avail_in = size;
        strm.next_out = result.data;
        strm.avail_out = compressed_size;
        
        ret = lzma_code(&strm, LZMA_FINISH);
        if(ret == LZMA_STREAM_END) {
            result.size = compressed_size - strm.avail_out;
        } else {
            free(result.data);
            result.data = NULL;
        }
    }
    
    lzma_end(&strm);
    return result;
}

// AES encryption (simplified)
buffer_t encrypt_aes(uint8_t *data, size_t size, uint8_t *key, uint8_t *iv) {
    buffer_t result = {NULL, 0};
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    
    // Create and initialize context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        return result;
    }
    
    // Initialize encryption
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    
    // Allocate buffer for ciphertext
    result.data = malloc(size + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    // Encrypt
    if(1 != EVP_EncryptUpdate(ctx, result.data, &len, data, size)) {
        free(result.data);
        result.data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    ciphertext_len = len;
    
    // Finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, result.data + len, &len)) {
        free(result.data);
        result.data = NULL;
        EVP_CIPHER_CTX_free(ctx);
        return result;
    }
    ciphertext_len += len;
    
    result.size = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// Packer detection signatures
typedef struct {
    char *name;
    uint8_t *signature;
    size_t sig_size;
} packer_signature_t;

packer_signature_t signatures[] = {
    {"UPX", (uint8_t*)"UPX!", 4},
    {"ASPack", (uint8_t*)"ASPack", 6},
    {"PECompact", (uint8_t*)"PEC2", 4},
    {"Themida", (uint8_t*)"Themida", 7},
    {NULL, NULL, 0}
};

// Detect packers in file
void detect_packers(uint8_t *data, size_t size) {
    printf("[*] Packer Detection:\n");
    int detected = 0;
    
    for(int i = 0; signatures[i].name != NULL; i++) {
        for(size_t j = 0; j < size - signatures[i].sig_size; j++) {
            if(memcmp(data + j, signatures[i].signature, signatures[i].sig_size) == 0) {
                printf("    [!] Detected: %s\n", signatures[i].name);
                detected = 1;
                break;
            }
        }
    }
    
    if(!detected) {
        printf("    [+] No known packers detected\n");
    }
}

// Analyze PE file structure
void analyze_pe_file(uint8_t *data, size_t size) {
    printf("[*] PE File Analysis:\n");
    
    // Check DOS header
    if(size < 0x40 || data[0] != 'M' || data[1] != 'Z') {
        printf("    [-] Not a valid PE file\n");
        return;
    }
    
    // Get PE header offset
    uint32_t pe_offset = *(uint32_t*)(data + 0x3C);
    if(pe_offset >= size - 0x100) {
        printf("    [-] Invalid PE header offset\n");
        return;
    }
    
    // Check PE signature
    if(memcmp(data + pe_offset, "PE\x00\x00", 4) != 0) {
        printf("    [-] Invalid PE signature\n");
        return;
    }
    
    // Get number of sections
    uint16_t num_sections = *(uint16_t*)(data + pe_offset + 6);
    printf("    [+] Number of sections: %d\n", num_sections);
    
    // Analyze sections
    uint32_t section_offset = pe_offset + 0xF8;
    for(int i = 0; i < num_sections && section_offset < size - 0x28; i++) {
        pe_section_t section;
        memcpy(section.name, data + section_offset, 8);
        section.name[8] = '\0';
        section.virtual_size = *(uint32_t*)(data + section_offset + 8);
        section.raw_size = *(uint32_t*)(data + section_offset + 16);
        
        // Calculate section entropy
        uint32_t section_data_offset = *(uint32_t*)(data + section_offset + 20);
        uint32_t section_data_size = section.raw_size;
        
        if(section_data_offset < size && section_data_size > 0 && 
           section_data_offset + section_data_size <= size) {
            section.entropy = calculate_entropy(data + section_data_offset, section_data_size);
            printf("    Section %s: VirtualSize=0x%X, RawSize=0x%X, Entropy=%.4f\n",
                   section.name, section.virtual_size, section.raw_size, section.entropy);
            
            if(section.entropy > ENTROPY_THRESHOLD) {
                printf("        [!] High entropy - possibly packed/encrypted\n");
            }
        }
        
        section_offset += 0x28;
    }
}

// Pack a file
void pack_file(const char *input_file, const char *output_file, 
               const char *compression, int encrypt) {
    printf("[*] Packing file: %s\n", input_file);
    
    // Read input file
    FILE *f = fopen(input_file, "rb");
    if(!f) {
        printf("[-] Cannot open input file\n");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *file_data = malloc(file_size);
    fread(file_data, 1, file_size, f);
    fclose(f);
    
    printf("[+] Original size: %zu bytes\n", file_size);
    printf("[+] Original entropy: %.4f\n", calculate_entropy(file_data, file_size));
    
    buffer_t compressed = {NULL, 0};
    
    // Apply compression
    if(strcmp(compression, "zlib") == 0) {
        compressed = compress_zlib(file_data, file_size);
        printf("[+] Zlib compression applied\n");
    } else if(strcmp(compression, "lzma") == 0) {
        compressed = compress_lzma(file_data, file_size);
        printf("[+] LZMA compression applied\n");
    } else {
        compressed.data = malloc(file_size);
        memcpy(compressed.data, file_data, file_size);
        compressed.size = file_size;
        printf("[+] No compression applied\n");
    }
    
    printf("[+] Compressed size: %zu bytes\n", compressed.size);
    printf("[+] Compressed entropy: %.4f\n", calculate_entropy(compressed.data, compressed.size));
    
    // Apply encryption
    if(encrypt) {
        uint8_t key[32], iv[16];
        RAND_bytes(key, sizeof(key));
        RAND_bytes(iv, sizeof(iv));
        
        buffer_t encrypted = encrypt_aes(compressed.data, compressed.size, key, iv);
        if(encrypted.data) {
            free(compressed.data);
            compressed = encrypted;
            printf("[+] AES encryption applied\n");
            printf("[+] Encrypted size: %zu bytes\n", compressed.size);
            printf("[+] Encrypted entropy: %.4f\n", calculate_entropy(compressed.data, compressed.size));
        }
    }
    
    // Write packed file
    f = fopen(output_file, "wb");
    if(f) {
        fwrite(compressed.data, 1, compressed.size, f);
        fclose(f);
        printf("[+] Packed file written: %s\n", output_file);
    } else {
        printf("[-] Cannot write output file\n");
    }
    
    free(compressed.data);
    free(file_data);
}

// Analyze a file
void analyze_file(const char *filename) {
    printf("[*] Analyzing file: %s\n", filename);
    
    FILE *f = fopen(filename, "rb");
    if(!f) {
        printf("[-] Cannot open file\n");
        return;
    }
    
    fseek(f, 0, SEEK_END);
    size_t file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *file_data = malloc(file_size);
    fread(file_data, 1, file_size, f);
    fclose(f);
    
    printf("[+] File size: %zu bytes\n", file_size);
    
    double entropy = calculate_entropy(file_data, file_size);
    printf("[+] Overall entropy: %.4f\n", entropy);
    
    if(entropy > ENTROPY_THRESHOLD) {
        printf("[!] High entropy - likely packed or encrypted\n");
    } else if(entropy > 6.0) {
        printf("[!] Moderate entropy - possibly packed\n");
    } else {
        printf("[+] Low entropy - likely uncompressed\n");
    }
    
    detect_packers(file_data, file_size);
    analyze_pe_file(file_data, file_size);
    
    free(file_data);
}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Obfuscation & Packer Research Toolkit\n");
        printf("Usage:\n");
        printf("  Pack:   %s pack <input> <output> [zlib|lzma|none] [encrypt]\n", argv[0]);
        printf("  Analyze: %s analyze <filename>\n", argv[0]);
        return 1;
    }
    
    srand(time(NULL));
    
    if(strcmp(argv[1], "pack") == 0 && argc >= 4) {
        const char *compression = (argc > 4) ? argv[4] : "zlib";
        int encrypt = (argc > 5) ? 1 : 1;
        pack_file(argv[2], argv[3], compression, encrypt);
    } else if(strcmp(argv[1], "analyze") == 0 && argc >= 3) {
        analyze_file(argv[2]);
    } else {
        printf("Invalid command or arguments\n");
        return 1;
    }
    
    return 0;
}
