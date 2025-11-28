#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <jwt.h>

#define BUFFER_SIZE 4096

typedef struct {
    char data[BUFFER_SIZE];
    size_t size;
} response_buffer;

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_buffer *buf = (response_buffer *)userp;
    
    size_t copy_size = realsize;
    if (buf->size + realsize >= BUFFER_SIZE) {
        copy_size = BUFFER_SIZE - buf->size - 1;
    }
    
    memcpy(&(buf->data[buf->size]), contents, copy_size);
    buf->size += copy_size;
    buf->data[buf->size] = 0;
    
    return realsize;
}

int validate_jwt(const char *token, const char *public_key) {
    jwt_t *jwt;
    int ret = jwt_decode(&jwt, token, (unsigned char*)public_key, strlen(public_key));
    if (ret != 0) {
        fprintf(stderr, "JWT decode failed: %d\n", ret);
        return -1;
    }
    
    // Check expiration
    time_t exp = jwt_get_grant_int(jwt, "exp");
    if (exp < time(NULL)) {
        jwt_free(jwt);
        return -2;
    }
    
    // Check audience
    const char *aud = jwt_get_grant(jwt, "aud");
    if (aud == NULL || strstr(aud, "service-a") == NULL) {
        jwt_free(jwt);
        return -3;
    }
    
    jwt_free(jwt);
    return 0;
}

int call_service_mtls(const char *url, const char *cert_file, const char *key_file) {
    CURL *curl;
    CURLcode res;
    response_buffer buf = {0};
    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cert_file);
        curl_easy_setopt(curl, CURLOPT_SSLKEY, key_file);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            return -1;
        }
        
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        printf("Response: %s\n", buf.data);
        printf("HTTP Code: %ld\n", http_code);
        
        curl_easy_cleanup(curl);
        return (http_code == 200) ? 0 : -1;
    }
    
    curl_global_cleanup();
    return -1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <test_type>\n", argv[0]);
        printf("Test types: mtls, jwt\n");
        return 2;
    }
    
    if (strcmp(argv[1], "mtls") == 0) {
        int result = call_service_mtls(
            "https://service-b:8080/health",
            "/certs/client.crt",
            "/certs/client.key"
        );
        
        printf("mTLS Test Result: %s\n", result == 0 ? "PASS" : "FAIL");
        return result;
    }
    else if (strcmp(argv[1], "jwt") == 0) {
        const char *test_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
        const char *public_key = "-----BEGIN PUBLIC KEY-----\n...";
        
        int result = validate_jwt(test_token, public_key);
        printf("JWT Test Result: %s\n", result == 0 ? "PASS" : "FAIL");
        return result;
    }
    else {
        fprintf(stderr, "Unknown test type: %s\n", argv[1]);
        return 2;
    }
}
