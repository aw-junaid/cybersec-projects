/**
 * Two-Factor Authentication Demo Implementation - C
 * Compile: gcc -o 2fa_demo 2fa_demo.c -lssl -lcrypto -lsqlite3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#define MAX_USERNAME 50
#define MAX_PASSWORD 100
#define MAX_PHONE 20
#define MAX_CODE 10
#define MAX_SECRET 100
#define SESSION_TIMEOUT 600 // 10 minutes

typedef struct {
    int user_id;
    char username[MAX_USERNAME];
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    char totp_secret[MAX_SECRET];
    char phone_number[MAX_PHONE];
    int two_factor_enabled;
    char two_factor_method[10];
} User;

typedef struct {
    char session_id[33];
    int user_id;
    char username[MAX_USERNAME];
    int two_factor_enabled;
    char two_factor_method[10];
    char totp_secret[MAX_SECRET];
    char phone_number[MAX_PHONE];
    time_t expires;
} Session;

typedef struct {
    char phone_number[MAX_PHONE];
    char code[MAX_CODE];
    time_t expires;
} SMSCode;

// Global variables
sqlite3* db = NULL;
Session* sessions[100] = {0};
int session_count = 0;
SMSCode sms_codes[50] = {0};
int sms_code_count = 0;

void generate_random_string(char* buffer, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(int i = 0; i < length - 1; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[length - 1] = '\0';
}

void sha256_hash(const char* input, char* output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = '\0';
}

int init_database() {
    int rc = sqlite3_open(":memory:", &db);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 0;
    }
    
    char* sql = "CREATE TABLE users ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT UNIQUE NOT NULL,"
                "password_hash TEXT NOT NULL,"
                "totp_secret TEXT,"
                "phone_number TEXT,"
                "two_factor_enabled BOOLEAN DEFAULT 0,"
                "two_factor_method TEXT DEFAULT 'totp');";
    
    char* err_msg = 0;
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    return 1;
}

int register_user(const char* username, const char* password, const char* phone) {
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    sha256_hash(password, password_hash);
    
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO users (username, password_hash, phone_number) VALUES ('%s', '%s', '%s');",
             username, password_hash, phone ? phone : "");
    
    char* err_msg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    printf("User %s registered successfully\n", username);
    return 1;
}

int enable_2fa(const char* username, const char* method) {
    char sql[512];
    
    if(strcmp(method, "totp") == 0) {
        char secret[33];
        generate_random_string(secret, 33);
        
        snprintf(sql, sizeof(sql),
                 "UPDATE users SET two_factor_enabled = 1, two_factor_method = 'totp', totp_secret = '%s' WHERE username = '%s';",
                 secret, username);
    } else {
        snprintf(sql, sizeof(sql),
                 "UPDATE users SET two_factor_enabled = 1, two_factor_method = '%s' WHERE username = '%s';",
                 method, username);
    }
    
    char* err_msg = 0;
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    printf("2FA enabled for %s using %s\n", username, method);
    return 1;
}

User* get_user(const char* username) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT * FROM users WHERE username = '%s';", username);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if(rc != SQLITE_OK) {
        return NULL;
    }
    
    if(sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return NULL;
    }
    
    User* user = malloc(sizeof(User));
    user->user_id = sqlite3_column_int(stmt, 0);
    strcpy(user->username, (const char*)sqlite3_column_text(stmt, 1));
    strcpy(user->password_hash, (const char*)sqlite3_column_text(stmt, 2));
    
    const char* totp_secret = (const char*)sqlite3_column_text(stmt, 3);
    strcpy(user->totp_secret, totp_secret ? totp_secret : "");
    
    const char* phone = (const char*)sqlite3_column_text(stmt, 4);
    strcpy(user->phone_number, phone ? phone : "");
    
    user->two_factor_enabled = sqlite3_column_int(stmt, 5);
    strcpy(user->two_factor_method, (const char*)sqlite3_column_text(stmt, 6));
    
    sqlite3_finalize(stmt);
    return user;
}

char* login_step1(const char* username, const char* password) {
    User* user = get_user(username);
    if(!user) {
        return NULL;
    }
    
    char password_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    sha256_hash(password, password_hash);
    
    if(strcmp(password_hash, user->password_hash) != 0) {
        free(user);
        return NULL;
    }
    
    // Generate session
    char* session_id = malloc(33);
    generate_random_string(session_id, 33);
    
    Session* session = malloc(sizeof(Session));
    strcpy(session->session_id, session_id);
    session->user_id = user->user_id;
    strcpy(session->username, user->username);
    session->two_factor_enabled = user->two_factor_enabled;
    strcpy(session->two_factor_method, user->two_factor_method);
    strcpy(session->totp_secret, user->totp_secret);
    strcpy(session->phone_number, user->phone_number);
    session->expires = time(NULL) + SESSION_TIMEOUT;
    
    sessions[session_count++] = session;
    free(user);
    
    return session_id;
}

int verify_totp(const char* secret, const char* code) {
    // Simplified TOTP verification
    // In real implementation, follow RFC 6238
    time_t now = time(NULL);
    time_t counter = now / 30; // 30-second intervals
    
    // Generate expected code (simplified)
    char expected_code[7];
    snprintf(expected_code, sizeof(expected_code), "%06ld", counter % 1000000);
    
    return strcmp(code, expected_code) == 0;
}

void send_sms_code(const char* phone_number, char* code) {
    // Generate random code
    snprintf(code, 7, "%06d", rand() % 1000000);
    
    // Store SMS code
    strcpy(sms_codes[sms_code_count].phone_number, phone_number);
    strcpy(sms_codes[sms_code_count].code, code);
    sms_codes[sms_code_count].expires = time(NULL) + 600; // 10 minutes
    sms_code_count++;
    
    printf("[SMS] Sent code %s to %s\n", code, phone_number);
}

int verify_sms_code(const char* phone_number, const char* code) {
    for(int i = 0; i < sms_code_count; i++) {
        if(strcmp(sms_codes[i].phone_number, phone_number) == 0) {
            if(time(NULL) > sms_codes[i].expires) {
                // Remove expired code
                for(int j = i; j < sms_code_count - 1; j++) {
                    sms_codes[j] = sms_codes[j + 1];
                }
                sms_code_count--;
                return 0;
            }
            
            if(strcmp(sms_codes[i].code, code) == 0) {
                // Remove used code
                for(int j = i; j < sms_code_count - 1; j++) {
                    sms_codes[j] = sms_codes[j + 1];
                }
                sms_code_count--;
                return 1;
            }
        }
    }
    return 0;
}

Session* find_session(const char* session_id) {
    for(int i = 0; i < session_count; i++) {
        if(strcmp(sessions[i]->session_id, session_id) == 0) {
            return sessions[i];
        }
    }
    return NULL;
}

int login_step2(const char* session_id, const char* code) {
    Session* session = find_session(session_id);
    if(!session) {
        return 0;
    }
    
    // Check session expiry
    if(time(NULL) > session->expires) {
        return 0;
    }
    
    if(!session->two_factor_enabled) {
        return 1; // No 2FA required
    }
    
    // Verify 2FA code
    if(strcmp(session->two_factor_method, "totp") == 0) {
        return verify_totp(session->totp_secret, code);
    } else if(strcmp(session->two_factor_method, "sms") == 0) {
        return verify_sms_code(session->phone_number, code);
    }
    
    return 0;
}

void cleanup_sessions() {
    time_t now = time(NULL);
    for(int i = 0; i < session_count; i++) {
        if(sessions[i] && now > sessions[i]->expires) {
            free(sessions[i]);
            sessions[i] = NULL;
        }
    }
}

void print_usage() {
    printf("Two-Factor Authentication Demo\n");
    printf("Usage:\n");
    printf("  register <username> <password> [phone]\n");
    printf("  enable-2fa <username> <totp|sms>\n");
    printf("  login <username> <password>\n");
    printf("  verify <session_id> <code>\n");
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        print_usage();
        return 1;
    }
    
    srand(time(NULL));
    
    if(!init_database()) {
        return 1;
    }
    
    if(strcmp(argv[1], "register") == 0 && argc >= 4) {
        const char* phone = argc > 4 ? argv[4] : NULL;
        register_user(argv[2], argv[3], phone);
    }
    else if(strcmp(argv[1], "enable-2fa") == 0 && argc >= 4) {
        enable_2fa(argv[2], argv[3]);
    }
    else if(strcmp(argv[1], "login") == 0 && argc >= 4) {
        char* session_id = login_step1(argv[2], argv[3]);
        if(session_id) {
            printf("Login step 1 successful\n");
            printf("Session ID: %s\n", session_id);
            
            // Check if 2FA is required
            Session* session = find_session(session_id);
            if(session && session->two_factor_enabled) {
                printf("2FA required using: %s\n", session->two_factor_method);
                
                if(strcmp(session->two_factor_method, "sms") == 0) {
                    char code[7];
                    send_sms_code(session->phone_number, code);
                    printf("SMS code sent: %s\n", code);
                } else {
                    printf("Please enter your TOTP code\n");
                }
            } else {
                printf("Login successful (no 2FA)\n");
            }
            
            free(session_id);
        } else {
            printf("Login failed\n");
        }
    }
    else if(strcmp(argv[1], "verify") == 0 && argc >= 4) {
        if(login_step2(argv[2], argv[3])) {
            printf("2FA verification successful\n");
            printf("Login completed\n");
        } else {
            printf("2FA verification failed\n");
        }
    }
    else {
        print_usage();
    }
    
    cleanup_sessions();
    sqlite3_close(db);
    return 0;
}
