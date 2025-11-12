/* csrf_checker.c
   Compile: gcc -o csrf_checker csrf_checker.c -lcurl
   Usage: ./csrf_checker <url>
   Notes: Read-only scanner. Requires libcurl development package.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

struct mem {
    char *data;
    size_t length;
};

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userp) {
    size_t realsz = size * nmemb;
    struct mem *mem = (struct mem*)userp;
    char *tmp = realloc(mem->data, mem->length + realsz + 1);
    if (!tmp) return 0;
    mem->data = tmp;
    memcpy(&(mem->data[mem->length]), ptr, realsz);
    mem->length += realsz;
    mem->data[mem->length] = 0;
    return realsz;
}

int contains_case_insensitive(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    size_t hn = strlen(hay), nn = strlen(needle);
    for (size_t i=0;i+nn<=hn;i++) {
        size_t j=0;
        for (; j<nn; j++) {
            char a = hay[i+j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (j==nn) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <url>\n", argv[0]);
        return 1;
    }
    const char *url = argv[1];
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "libcurl init failed\n");
        return 1;
    }
    struct mem chunk = {0};
    struct curl_slist *hdrs = NULL;
    char header_buf[1024];

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);

    // collect headers manually for Set-Cookie
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &chunk);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.data);
        return 1;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    printf("HTTP %ld\n", http_code);

    // Look for Set-Cookie and SameSite
    if (chunk.length > 0 && contains_case_insensitive(chunk.data, "Set-Cookie:")) {
        printf("\nSet-Cookie header(s) present (raw):\n");
        const char *p = chunk.data;
        while ((p = strstr(p, "Set-Cookie:")) != NULL) {
            const char *eol = strstr(p, "\r\n");
            if (!eol) eol = p + strlen(p);
            size_t len = eol - p;
            if (len > 0 && len < sizeof(header_buf)) {
                strncpy(header_buf, p, len);
                header_buf[len] = 0;
                printf("  %s\n", header_buf);
                if (!contains_case_insensitive(header_buf, "samesite")) {
                    printf("    -> Missing SameSite attribute (recommend Lax or Strict)\n");
                }
            }
            p = eol ? eol+2 : p+9;
        }
    } else {
        printf("\nNo Set-Cookie headers detected in response headers.\n");
    }

    // Simple form checks (very heuristic)
    const char *html = chunk.data ? chunk.data : "";
    int form_count = 0, risk_forms = 0;
    const char *pos = html;
    while ((pos = strcasestr(pos, "<form")) != NULL) {
        form_count++;
        const char *endform = strcasestr(pos, "</form>");
        size_t blocklen = endform ? (endform - pos) : strlen(pos);
        char *block = malloc(blocklen + 1);
        strncpy(block, pos, blocklen);
        block[blocklen] = 0;

        // detect method
        int is_post = contains_case_insensitive(block, "method=\"post\"") || contains_case_insensitive(block, "method='post'");

        // detect hidden inputs with common names
        const char *names[] = {
            "csrf", "csrf_token","csrf-token","authenticity_token",
            "_csrf","__requestverificationtoken","token","xsrf-token","anti_csrf", NULL
        };
        int token_found = 0;
        for (int i=0; names[i]; ++i) {
            if (contains_case_insensitive(block, names[i])) { token_found = 1; break; }
        }
        if (is_post && !token_found) {
            printf("\nForm %d: POST form without detectable CSRF token (heuristic)\n", form_count);
            risk_forms++;
        }
        free(block);
        pos = endform ? endform + 7 : pos + 5;
    }

    printf("\nForms found (heuristic): %d\n", form_count);
    if (risk_forms) {
        printf("Potentially risky POST forms without CSRF token: %d\n", risk_forms);
    } else {
        printf("No obviously risky POST forms detected by this heuristic.\n");
    }

    printf("\nRecommendations:\n - Use per-request server-side CSRF tokens in forms.\n - Set SameSite cookie attribute (Lax/Strict) where suitable.\n - Avoid state-changing GET endpoints.\n - Implement server-side Referer/Origin checks for sensitive endpoints.\n");

    curl_easy_cleanup(curl);
    free(chunk.data);
    return 0;
}
