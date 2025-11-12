/*
 upload_client.c - HTTP multipart uploader using libcurl (client)
 Compile: gcc -o upload_client upload_client.c -lcurl
 Usage: ./upload_client http://127.0.0.1:8000/upload token filename
 Notes: This performs a standard multipart/form-data POST.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <url> <token> <file>\n", argv[0]);
        return 1;
    }
    const char *url = argv[1];
    const char *token = argv[2];
    const char *file = argv[3];

    CURL *c = curl_easy_init();
    if (!c) { fprintf(stderr, "curl init failed\n"); return 1; }

    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_FILE, file,
                 CURLFORM_END);

    struct curl_slist *headers = NULL;
    char xtoken[512];
    snprintf(xtoken, sizeof(xtoken), "X-UPLOAD-TOKEN: %s", token);
    headers = curl_slist_append(headers, xtoken);

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(c, CURLOPT_HTTPPOST, formpost);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(c);
    if (res != CURLE_OK) {
        fprintf(stderr, "upload failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(c);
    curl_formfree(formpost);
    curl_slist_free_all(headers);
    return (res == CURLE_OK) ? 0 : 1;
}
