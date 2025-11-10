/*
dir_bruteforce.c — Directory Brute-force Tool in C
Usage:
  ./dir_bruteforce https://example.com wordlist.txt
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
    struct memory *mem = (struct memory *)userdata;
    size_t realsize = size * nmemb;
    mem->data = realloc(mem->data, mem->size + realsize + 1);
    if (mem->data == NULL) return 0;
    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}

int check_url(const char *base, const char *path) {
    CURL *curl;
    CURLcode res;
    long response_code = 0;
    struct memory chunk = {0};

    char url[512];
    snprintf(url, sizeof(url), "%s/%s", base, path);

    curl = curl_easy_init();
    if (!curl) return -1;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DirBrute-C/1.0");

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code != 404 && response_code != 400) {
            printf("[FOUND] %s (HTTP %ld)\n", url, response_code);
        }
    }
    curl_easy_cleanup(curl);
    free(chunk.data);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <base_url> <wordlist>\n", argv[0]);
        return 1;
    }

    char *base = argv[1];
    FILE *f = fopen(argv[2], "r");
    if (!f) {
        perror("wordlist");
        return 1;
    }

    char word[256];
    printf("[+] Starting directory brute-force on %s\n", base);
    while (fgets(word, sizeof(word), f)) {
        word[strcspn(word, "\n")] = 0;
        check_url(base, word);
    }

    fclose(f);
    return 0;
}
