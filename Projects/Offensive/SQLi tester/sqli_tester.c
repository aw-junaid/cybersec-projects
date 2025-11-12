/* sqli_tester.c - Safe, lab-only SQLi detection (C, libcurl)
   Compile:
     sudo apt install libcurl4-openssl-dev
     gcc -o sqli_tester sqli_tester.c -lcurl
   Usage:
     ./sqli_tester "http://127.0.0.1:8000/search?q=test"
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/sha.h>   /* for hashing responses (libssl) */

struct mem { char *data; size_t size; };

size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsz = size * nmemb;
    struct mem *m = (struct mem*)userdata;
    char *n = realloc(m->data, m->size + realsz + 1);
    if (!n) return 0;
    m->data = n;
    memcpy(m->data + m->size, ptr, realsz);
    m->size += realsz;
    m->data[m->size] = 0;
    return realsz;
}

void sha256_hex(const unsigned char *buf, size_t len, char *outhex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(buf, len, hash);
    for (int i=0;i<SHA256_DIGEST_LENGTH;i++) sprintf(outhex + i*2, "%02x", hash[i]);
}

int send_get(const char *url, long *http_code, size_t *body_len, char **body_copy, char *sha256_out) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;
    struct mem m = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        if (m.data) free(m.data);
        return 2;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    *body_len = m.size;
    if (body_copy) *body_copy = m.data;
    else free(m.data);
    if (sha256_out) sha256_hex((unsigned char*)m.data, m.size, sha256_out);
    curl_easy_cleanup(curl);
    return 0;
}

char *url_with_param(const char *base, const char *param, const char *value) {
    /* naive: replace param value in base (expects param=... present) */
    char *out = malloc(strlen(base) + strlen(value) + 128);
    char *pos = strstr(base, param);
    if (!pos) {
        sprintf(out, "%s", base);
        return out;
    }
    /* find '=' after param */
    char *eq = strchr(pos, '=');
    if (!eq) { sprintf(out, "%s", base); return out; }
    /* find end of param value (ampersand or end) */
    char *amp = strchr(eq, '&');
    int prefix_len = eq - base + 1;
    if (amp) {
        int suffix_len = strlen(amp);
        strncpy(out, base, prefix_len);
        out[prefix_len] = 0;
        strcat(out, value);
        strcat(out, amp);
    } else {
        strncpy(out, base, prefix_len);
        out[prefix_len] = 0;
        strcat(out, value);
    }
    return out;
}

int contains_sql_error(const char *body) {
    const char *sigs[] = {"sql syntax","mysql","syntax error","sqlite","odbc","pg_query","psql","sql error"};
    for (size_t i=0;i<sizeof(sigs)/sizeof(sigs[0]);i++) {
        if (body && strcasestr(body, sigs[i])) return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <url-with-param>\n", argv[0]);
        return 1;
    }
    const char *url = argv[1];
    const char *param = "q"; /* simplistic: assumes ?q= present; you can expand parsing */
    char *baseline_url = url_with_param(url, param, "SAFE_TEST_12345");
    char *err_url = url_with_param(url, param, "'");
    char *true_url = url_with_param(url, param, "' OR '1'='1");
    char *false_url = url_with_param(url, param, "' OR '1'='2");

    long bcode=0, pcode=0, tcode=0, fcode=0;
    size_t blen=0, plen=0, tlen=0, flen=0;
    char bhash[SHA256_DIGEST_LENGTH*2+1]={0}, phash[SHA256_DIGEST_LENGTH*2+1]={0}, thash[SHA256_DIGEST_LENGTH*2+1]={0}, fhash[SHA256_DIGEST_LENGTH*2+1]={0};
    char *bbody=NULL, *pbody=NULL, *tbody=NULL, *fbody=NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if (send_get(baseline_url, &bcode, &blen, &bbody, bhash) != 0) { fprintf(stderr,"baseline req failed\n"); }
    if (send_get(err_url, &pcode, &plen, &pbody, phash) != 0) { /* ignore */ }
    if (send_get(true_url, &tcode, &tlen, &tbody, thash) != 0) { /* ignore */ }
    if (send_get(false_url, &fcode, &flen, &fbody, fhash) != 0) { /* ignore */ }

    printf("Baseline: code=%ld len=%zu hash=%s\n", bcode, blen, bhash);
    printf("Error-probe: code=%ld len=%zu\n", pcode, plen);
    if (pbody && contains_sql_error(pbody)) printf("[EVIDENCE] SQL error strings detected in error-probe response\n");
    printf("Bool-true: code=%ld len=%zu hash=%s\n", tcode, tlen, thash);
    printf("Bool-false: code=%ld len=%zu hash=%s\n", fcode, flen, fhash);
    if (strcmp(thash, fhash) != 0) {
        printf("[EVIDENCE] true/false responses differ -> possible boolean-based injection\n");
        if (strcmp(bhash, fhash) == 0) printf("  baseline matches false response (common pattern)\n");
    } else {
        printf("No boolean difference detected for provided payloads.\n");
    }

    /* cleanup */
    if (bbody) free(bbody);
    if (pbody) free(pbody);
    if (tbody) free(tbody);
    if (fbody) free(fbody);
    free(baseline_url); free(err_url); free(true_url); free(false_url);
    curl_global_cleanup();
    return 0;
}
