#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <sqlite3.h>

#define MAX_IOCS 1000
#define MAX_IOC_LENGTH 256
#define MAX_CONTENT_LENGTH 100000

typedef struct {
    char ioc[MAX_IOC_LENGTH];
    char type[20];
    char source[100];
    time_t timestamp;
} IOC;

typedef struct {
    IOC iocs[MAX_IOCS];
    int count;
} IOCDatabase;

// Regular expressions for IOC extraction
const char* ip_regex = "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";
const char* domain_regex = "([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.([a-zA-Z]{2,}))";
const char* md5_regex = "([a-fA-F0-9]{32})";
const char* sha1_regex = "([a-fA-F0-9]{40})";
const char* sha256_regex = "([a-fA-F0-9]{64})";
const char* url_regex = "(https?://[^\\s<>\"]+)";
const char* email_regex = "([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,})";
const char* cve_regex = "(CVE-\\d{4}-\\d{4,})";

int extract_matches(const char* content, const char* pattern, IOC* iocs, int* count, const char* type, const char* source) {
    regex_t regex;
    regmatch_t matches[2];
    int ret;
    char* cursor = (char*)content;
    
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        return -1;
    }
    
    while (*count < MAX_IOCS && (ret = regexec(&regex, cursor, 2, matches, 0)) == 0) {
        // Extract matched IOC
        int start = matches[1].rm_so;
        int end = matches[1].rm_eo;
        int length = end - start;
        
        if (length < MAX_IOC_LENGTH) {
            strncpy(iocs[*count].ioc, cursor + start, length);
            iocs[*count].ioc[length] = '\0';
            strcpy(iocs[*count].type, type);
            strcpy(iocs[*count].source, source);
            iocs[*count].timestamp = time(NULL);
            (*count)++;
        }
        
        cursor += matches[0].rm_eo;
    }
    
    regfree(&regex);
    return 0;
}

void extract_iocs(const char* content, const char* source, IOCDatabase* db) {
    printf("Extracting IOCs from: %s\n", source);
    
    extract_matches(content, ip_regex, db->iocs, &db->count, "ip", source);
    extract_matches(content, domain_regex, db->iocs, &db->count, "domain", source);
    extract_matches(content, md5_regex, db->iocs, &db->count, "md5", source);
    extract_matches(content, sha1_regex, db->iocs, &db->count, "sha1", source);
    extract_matches(content, sha256_regex, db->iocs, &db->count, "sha256", source);
    extract_matches(content, url_regex, db->iocs, &db->count, "url", source);
    extract_matches(content, email_regex, db->iocs, &db->count, "email", source);
    extract_matches(content, cve_regex, db->iocs, &db->count, "cve", source);
}

void init_database(sqlite3** db) {
    int rc = sqlite3_open("iocs.db", db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(*db));
        return;
    }
    
    char* sql = "CREATE TABLE IF NOT EXISTS iocs ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "ioc TEXT UNIQUE,"
                "type TEXT,"
                "source TEXT,"
                "first_seen DATETIME,"
                "last_seen DATETIME);";
    
    char* err_msg = 0;
    rc = sqlite3_exec(*db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    } else {
        printf("Database initialized successfully\n");
    }
}

void store_iocs(sqlite3* db, IOCDatabase* ioc_db) {
    char* sql = "INSERT OR REPLACE INTO iocs (ioc, type, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }
    
    for (int i = 0; i < ioc_db->count; i++) {
        sqlite3_bind_text(stmt, 1, ioc_db->iocs[i].ioc, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, ioc_db->iocs[i].type, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, ioc_db->iocs[i].source, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, ioc_db->iocs[i].timestamp);
        sqlite3_bind_int64(stmt, 5, ioc_db->iocs[i].timestamp);
        
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "Execution failed: %s\n", sqlite3_errmsg(db));
        }
        
        sqlite3_reset(stmt);
    }
    
    sqlite3_finalize(stmt);
    printf("Stored %d IOCs in database\n", ioc_db->count);
}

void search_iocs(sqlite3* db, const char* search_term) {
    char* sql = "SELECT ioc, type, source, first_seen FROM iocs WHERE ioc LIKE ? OR type = ? ORDER BY first_seen DESC";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }
    
    char search_pattern[300];
    snprintf(search_pattern, sizeof(search_pattern), "%%%s%%", search_term);
    
    sqlite3_bind_text(stmt, 1, search_pattern, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, search_term, -1, SQLITE_STATIC);
    
    printf("Search results for '%s':\n", search_term);
    printf("%-40s %-10s %-20s %s\n", "IOC", "Type", "Source", "First Seen");
    printf("%-40s %-10s %-20s %s\n", "---", "----", "------", "----------");
    
    int result_count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* ioc = (const char*)sqlite3_column_text(stmt, 0);
        const char* type = (const char*)sqlite3_column_text(stmt, 1);
        const char* source = (const char*)sqlite3_column_text(stmt, 2);
        const char* first_seen = (const char*)sqlite3_column_text(stmt, 3);
        
        printf("%-40s %-10s %-20s %s\n", ioc, type, source, first_seen);
        result_count++;
    }
    
    if (result_count == 0) {
        printf("No results found\n");
    }
    
    sqlite3_finalize(stmt);
}

int main() {
    printf("Threat Intelligence IOC Extractor - C Implementation\n");
    printf("FOR RESEARCH AND EDUCATIONAL PURPOSES ONLY\n\n");
    
    sqlite3* db;
    init_database(&db);
    
    IOCDatabase ioc_db = {0};
    
    // Example content with embedded IOCs
    const char* sample_content = 
        "Malware sample found at 192.168.1.100 connecting to evil.com\n"
        "MD5: 5d41402abc4b2a76b9719d911017c592\n"
        "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "Contact: attacker@example.com\n"
        "CVE-2021-44228 detected\n"
        "Download from http://malicious.com/payload.exe";
    
    extract_iocs(sample_content, "sample_analysis", &ioc_db);
    
    // Store in database
    store_iocs(db, &ioc_db);
    
    // Search examples
    printf("\n");
    search_iocs(db, "192.168");
    printf("\n");
    search_iocs(db, "md5");
    
    sqlite3_close(db);
    
    return 0;
}
