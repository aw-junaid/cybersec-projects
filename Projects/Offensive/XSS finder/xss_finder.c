/*
xss_finder.c — Simple reflected XSS detector.
Usage:
  ./xss_finder "https://example.com/search?q=test"
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct memory {
    char *data;
    size_t size;
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct memory *mem = (struct memory *)userdata;
    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if (!mem->data) return 0;
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

void test_xss(const char *url, const char *payload) {
    CURL *curl;
    CURLcode res;
    long code = 0;
    struct memory chunk = {0};

    char test_url[1024];
    snprintf(test_url, sizeof(test_url), "%s%s", url, payload);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, test_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
            if (strstr(chunk.data, payload)) {
                printf("[VULNERABLE] Payload reflected in response for %s\n", test_url);
            } else {
                printf("[SAFE] Payload sanitized for %s\n", test_url);
            }
        } else {
            fprintf(stderr, "[ERROR] %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        free(chunk.data);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <url_with_parameter>\n", argv[0]);
        return 1;
    }

    const char *base = argv[1];
    const char *payloads[] = {
        "<script>alert('XSS')</script>",
        "'><img src=x onerror=alert(1)>",
        "\" onmouseover=alert('XSS')>"
    };

    for (int i = 0; i < 3; i++) {
        printf("[*] Testing payload: %s\n", payloads[i]);
        test_xss(base, payloads[i]);
    }

    return 0;
}
