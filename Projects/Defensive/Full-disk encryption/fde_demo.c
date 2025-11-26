#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define SECTOR_SIZE 512
#define KEY_SIZE 32
#define IV_SIZE 16
#define SALT_SIZE 16

typedef struct {
    unsigned char key_data[KEY_SIZE];
    char key_id[64];
    time_t created;
    time_t expires;
    int version;
    char algorithm[32];
} encryption_key_t;

typedef struct {
    encryption_key_t* keys;
    int key_count;
    int capacity;
} key_manager_t;

// Initialize key manager
key_manager_t* key_manager_init() {
    key_manager_t* km = malloc(sizeof(key_manager_t));
    km->capacity = 10;
    km->key_count = 0;
    km->keys = malloc(km->capacity * sizeof(encryption_key_t));
    return km;
}

// Generate cryptographically secure random key
int generate_secure_key(unsigned char* key, int key_size) {
    if (RAND_bytes(key, key_size) != 1) {
        return 0; // Failure
    }
    return 1; // Success
}

// Derive key from passphrase using PBKDF2
int derive_key_from_passphrase(const char* passphrase, const unsigned char* salt, 
                              unsigned char* derived_key, int iterations) {
    return PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), 
                            salt, SALT_SIZE, iterations, 
                            EVP_sha256(), KEY_SIZE, derived_key);
}

// Encrypt a single sector using AES-256-CBC
int encrypt_sector(const unsigned char* plaintext, int plaintext_len,
                  const unsigned char* key, const unsigned char* iv,
                  unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypt a single sector
int decrypt_sector(const unsigned char* ciphertext, int ciphertext_len,
                  const unsigned char* key, const unsigned char* iv,
                  unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Add key to key manager
void key_manager_add_key(key_manager_t* km, const unsigned char* key_data, 
                        const char* key_id, int validity_days) {
    if (km->key_count >= km->capacity) {
        km->capacity *= 2;
        km->keys = realloc(km->keys, km->capacity * sizeof(encryption_key_t));
    }

    encryption_key_t* new_key = &km->keys[km->key_count];
    memcpy(new_key->key_data, key_data, KEY_SIZE);
    strncpy(new_key->key_id, key_id, sizeof(new_key->key_id) - 1);
    new_key->created = time(NULL);
    new_key->expires = new_key->created + (validity_days * 24 * 60 * 60);
    new_key->version = km->key_count + 1;
    strcpy(new_key->algorithm, "AES-256-CBC");

    km->key_count++;
}

// Demo full-disk encryption simulation
void demo_disk_encryption() {
    printf("\n=== FULL-DISK ENCRYPTION DEMO ===\n");

    // Generate encryption key
    unsigned char key[KEY_SIZE];
    if (!generate_secure_key(key, KEY_SIZE)) {
        printf("Error: Failed to generate secure key\n");
        return;
    }

    printf("Generated encryption key: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
    }
    printf("...\n");

    // Sample data to encrypt
    const char* sample_data = "This is a sample sector that would be encrypted on disk. "
                             "Full-disk encryption protects data at rest by encrypting "
                             "entire disk volumes, including system files and user data.";
    
    unsigned char iv[IV_SIZE];
    unsigned char ciphertext[SECTOR_SIZE * 2]; // Buffer for encrypted data
    unsigned char decrypted[SECTOR_SIZE];

    // Generate random IV
    if (!generate_secure_key(iv, IV_SIZE)) {
        printf("Error: Failed to generate IV\n");
        return;
    }

    // Encrypt the sector
    int ciphertext_len = encrypt_sector(
        (const unsigned char*)sample_data, strlen(sample_data), 
        key, iv, ciphertext
    );

    if (ciphertext_len == -1) {
        printf("Error: Encryption failed\n");
        return;
    }

    printf("Original data length: %zu bytes\n", strlen(sample_data));
    printf("Encrypted data length: %d bytes\n", ciphertext_len);

    // Decrypt the sector
    int decrypted_len = decrypt_sector(ciphertext, ciphertext_len, key, iv, decrypted);
    
    if (decrypted_len == -1) {
        printf("Error: Decryption failed\n");
        return;
    }

    decrypted[decrypted_len] = '\0'; // Null-terminate

    printf("Decryption successful: %s\n", 
           strcmp(sample_data, (char*)decrypted) == 0 ? "YES" : "NO");
    printf("Data integrity verified!\n");
}

// Demo key management
void demo_key_management() {
    printf("\n=== KEY MANAGEMENT DEMO ===\n");

    key_manager_t* km = key_manager_init();

    // Generate multiple keys
    unsigned char key1[KEY_SIZE], key2[KEY_SIZE];
    generate_secure_key(key1, KEY_SIZE);
    generate_secure_key(key2, KEY_SIZE);

    // Add keys to manager
    key_manager_add_key(km, key1, "master_key", 365);
    key_manager_add_key(km, key2, "data_key", 90);

    printf("Key Manager Contents:\n");
    for (int i = 0; i < km->key_count; i++) {
        encryption_key_t* key = &km->keys[i];
        printf("  Key %d:\n", i + 1);
        printf("    ID: %s\n", key->key_id);
        printf("    Version: %d\n", key->version);
        printf("    Created: %s", ctime(&key->created));
        printf("    Expires: %s", ctime(&key->expires));
        printf("    Algorithm: %s\n", key->algorithm);
    }

    free(km->keys);
    free(km);
}

int main() {
    printf("Full-Disk Encryption & Key Management Demo\n");
    printf("==========================================\n");

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    demo_disk_encryption();
    demo_key_management();

    // Cleanup OpenSSL
    EVP_cleanup();

    return 0;
}
