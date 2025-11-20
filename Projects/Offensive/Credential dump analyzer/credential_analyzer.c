#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sqlite3.h>
#include <time.h>

#define MAX_CREDENTIALS 100000
#define MAX_USERNAME_LENGTH 256
#define MAX_PASSWORD_LENGTH 256
#define MAX_SOURCE_LENGTH 100
#define MAX_EMAIL_LENGTH 256
#define MAX_DOMAIN_LENGTH 100

typedef struct {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char source[MAX_SOURCE_LENGTH];
    char domain[MAX_DOMAIN_LENGTH];
    char email[MAX_EMAIL_LENGTH];
    int is_hash;
} Credential;

typedef struct {
    Credential* credentials;
    int count;
    int capacity;
} CredentialList;

// Initialize credential list
void init_credential_list(CredentialList* list, int initial_capacity) {
    list->credentials = malloc(initial_capacity * sizeof(Credential));
    list->count = 0;
    list->capacity = initial_capacity;
}

// Add credential to list
int add_credential(CredentialList* list, const char* username, const char* password, const char* source) {
    if (list->count >= list->capacity) {
        // Resize array
        int new_capacity = list->capacity * 2;
        Credential* new_credentials = realloc(list->credentials, new_capacity * sizeof(Credential));
        if (!new_credentials) {
            return -1; // Allocation failed
        }
        list->credentials = new_credentials;
        list->capacity = new_capacity;
    }
    
    Credential* cred = &list->credentials[list->count];
    
    strncpy(cred->username, username, MAX_USERNAME_LENGTH - 1);
    strncpy(cred->password, password, MAX_PASSWORD_LENGTH - 1);
    strncpy(cred->source, source, MAX_SOURCE_LENGTH - 1);
    
    // Extract domain from username/email
    extract_domain(cred->username, cred->domain, MAX_DOMAIN_LENGTH);
    extract_email(cred->username, cred->email, MAX_EMAIL_LENGTH);
    
    // Detect if password is a hash
    cred->is_hash = is_likely_hash(cred->password);
    
    list->count++;
    return 0;
}

// Extract domain from username
void extract_domain(const char* username, char* domain, size_t domain_size) {
    const char* at_pos = strchr(username, '@');
    if (at_pos) {
        strncpy(domain, at_pos + 1, domain_size - 1);
        domain[domain_size - 1] = '\0';
    } else {
        domain[0] = '\0';
    }
}

// Extract email from username
void extract_email(const char* username, char* email, size_t email_size) {
    // Simple email pattern matching
    regex_t regex;
    int reti;
    
    reti = regcomp(&regex, "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", REG_EXTENDED);
    if (reti) {
        email[0] = '\0';
        return;
    }
    
    regmatch_t matches[1];
    reti = regexec(&regex, username, 1, matches, 0);
    if (!reti) {
        int start = matches[0].rm_so;
        int end = matches[0].rm_eo;
        int length = end - start;
        
        if (length < email_size) {
            strncpy(email, username + start, length);
            email[length] = '\0';
        } else {
            email[0] = '\0';
        }
    } else {
        email[0] = '\0';
    }
    
    regfree(&regex);
}

// Check if string is likely a hash
int is_likely_hash(const char* str) {
    int len = strlen(str);
    
    // MD5 (32 hex chars)
    if (len == 32) {
        int i;
        for (i = 0; i < len; i++) {
            if (!isxdigit(str[i])) return 0;
        }
        return 1;
    }
    
    // SHA1 (40 hex chars)
    if (len == 40) {
        int i;
        for (i = 0; i < len; i++) {
            if (!isxdigit(str[i])) return 0;
        }
        return 1;
    }
    
    // SHA256 (64 hex chars)
    if (len == 64) {
        int i;
        for (i = 0; i < len; i++) {
            if (!isxdigit(str[i])) return 0;
        }
        return 1;
    }
    
    return 0;
}

// Parse colon-separated credential file
int parse_colon_file(const char* filename, CredentialList* list, const char* source) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    char line[1024];
    int line_count = 0;
    
    while (fgets(line, sizeof(line), file) && list->count < MAX_CREDENTIALS) {
        line_count++;
        
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        if (strlen(line) == 0) continue;
        
        // Split by colon
        char* colon_pos = strchr(line, ':');
        if (colon_pos) {
            *colon_pos = '\0';
            char* username = line;
            char* password = colon_pos + 1;
            
            // Trim whitespace
            char* end = username + strlen(username) - 1;
            while (end > username && isspace(*end)) end--;
            *(end + 1) = '\0';
            
            end = password + strlen(password) - 1;
            while (end > password && isspace(*end)) end--;
            *(end + 1) = '\0';
            
            if (strlen(username) > 0 && strlen(password) > 0) {
                add_credential(list, username, password, source);
            }
        }
    }
    
    fclose(file);
    printf("Parsed %d credentials from %s\n", line_count, filename);
    return line_count;
}

// Analyze credential list
void analyze_credentials(const CredentialList* list) {
    printf("\nCredential Analysis Report\n");
    printf("==========================\n");
    printf("Total credentials: %d\n", list->count);
    
    // Count unique usernames and passwords
    int unique_usernames = 0;
    int unique_passwords = 0;
    
    // Simple analysis - in real implementation, use proper data structures
    printf("\nTop 10 most common passwords:\n");
    
    // Password length analysis
    int short_passwords = 0;
    int hash_count = 0;
    
    for (int i = 0; i < list->count; i++) {
        const Credential* cred = &list->credentials[i];
        
        if (strlen(cred->password) < 8) {
            short_passwords++;
        }
        
        if (cred->is_hash) {
            hash_count++;
        }
    }
    
    printf("Short passwords (<8 chars): %d (%.1f%%)\n", 
           short_passwords, (short_passwords * 100.0) / list->count);
    printf("Hashed passwords: %d (%.1f%%)\n", 
           hash_count, (hash_count * 100.0) / list->count);
    
    // Domain analysis
    printf("\nDomain Analysis:\n");
    // In real implementation, count domains and show top ones
}

// Initialize SQLite database
int init_database(const char* db_path) {
    sqlite3* db;
    char* err_msg = 0;
    int rc;
    
    rc = sqlite3_open(db_path, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    char* sql = "CREATE TABLE IF NOT EXISTS credentials ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "username TEXT,"
                "password TEXT,"
                "source TEXT,"
                "domain TEXT,"
                "email TEXT,"
                "is_hash INTEGER,"
                "import_date DATETIME DEFAULT CURRENT_TIMESTAMP);";
    
    rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return -1;
    }
    
    sqlite3_close(db);
    printf("Database initialized: %s\n", db_path);
    return 0;
}

// Store credentials in database
int store_credentials(const CredentialList* list, const char* db_path) {
    sqlite3* db;
    char* err_msg = 0;
    int rc;
    
    rc = sqlite3_open(db_path, &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // Begin transaction
    sqlite3_exec(db, "BEGIN TRANSACTION", 0, 0, 0);
    
    for (int i = 0; i < list->count; i++) {
        const Credential* cred = &list->credentials[i];
        
        char sql[1024];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO credentials (username, password, source, domain, email, is_hash) "
                 "VALUES ('%s', '%s', '%s', '%s', '%s', %d);",
                 cred->username, cred->password, cred->source, 
                 cred->domain, cred->email, cred->is_hash);
        
        rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", err_msg);
            sqlite3_free(err_msg);
            break;
        }
    }
    
    // Commit transaction
    sqlite3_exec(db, "COMMIT", 0, 0, 0);
    sqlite3_close(db);
    
    printf("Stored %d credentials in database\n", list->count);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <credential_files...>\n", argv[0]);
        printf("       %s --db <database_file> <credential_files...>\n", argv[0]);
        return 1;
    }
    
    printf("Credential Dump Analyzer - C Implementation\n");
    printf("FOR AUTHORIZED SECURITY RESEARCH ONLY\n\n");
    
    CredentialList cred_list;
    init_credential_list(&cred_list, 1000);
    
    int use_database = 0;
    const char* db_path = "credentials.db";
    
    // Parse arguments
    int file_start = 1;
    if (argc >= 3 && strcmp(argv[1], "--db") == 0) {
        use_database = 1;
        db_path = argv[2];
        file_start = 3;
        init_database(db_path);
    }
    
    // Parse all credential files
    for (int i = file_start; i < argc; i++) {
        parse_colon_file(argv[i], &cred_list, argv[i]);
    }
    
    if (cred_list.count == 0) {
        printf("No credentials found to analyze\n");
        free(cred_list.credentials);
        return 1;
    }
    
    // Analyze credentials
    analyze_credentials(&cred_list);
    
    // Store in database if requested
    if (use_database) {
        store_credentials(&cred_list, db_path);
    }
    
    // Cleanup
    free(cred_list.credentials);
    
    return 0;
}
