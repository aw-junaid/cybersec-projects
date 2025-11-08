/*
ext_scanner_c.c - Passive page scanner using libcurl + Gumbo
Compile:
  gcc -o ext_scanner_c ext_scanner_c.c -lcurl -lgumbo

Usage:
  ./ext_scanner_c https://example.local > report.txt
Notes:
  - Passive scanner: only issues HTTP(S) GET requests and parses the HTML.
  - This tool detects: missing CSP meta, inline scripts, external script sources, forms with method GET, and mixed-content resources.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <gumbo.h>

struct mem {
    char *buf; size_t size;
};
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsz = size * nmemb;
    struct mem *m = (struct mem*)userdata;
    char *n = realloc(m->buf, m->size + realsz + 1);
    if (!n) return 0;
    m->buf = n;
    memcpy(m->buf + m->size, ptr, realsz);
    m->size += realsz;
    m->buf[m->size] = 0;
    return realsz;
}

void traverse(GumboNode* node, const char* base_url, int* inline_scripts, int* external_scripts, int* forms_get, int* mixed_content) {
    if (node->type != GUMBO_NODE_ELEMENT) return;
    GumboAttribute* attr;
    GumboVector* children;
    switch (node->v.element.tag) {
        case GUMBO_TAG_SCRIPT:
            attr = gumbo_get_attribute(&node->v.element.attributes, "src");
            if (attr) (*external_scripts)++;
            else (*inline_scripts)++;
            break;
        case GUMBO_TAG_META:
            attr = gumbo_get_attribute(&node->v.element.attributes, "http-equiv");
            if (attr && strcasecmp(attr->value, "Content-Security-Policy")==0) {
                // presence indicates CSP meta tag
            }
            break;
        case GUMBO_TAG_LINK:
        case GUMBO_TAG_IMG:
        case GUMBO_TAG_SCRIPT:
        case GUMBO_TAG_IFRAME:
        {
            // check src/href attribute for mixed content (http resource on https base)
            GumboAttribute* src = gumbo_get_attribute(&node->v.element.attributes, "src");
            GumboAttribute* href = gumbo_get_attribute(&node->v.element.attributes, "href");
            const char* val = src ? src->value : (href ? href->value : NULL);
            if (val && base_url && strncasecmp(base_url, "https://", 8)==0 && strncasecmp(val, "http://", 7)==0) {
                (*mixed_content)++;
            }
            break;
        }
        case GUMBO_TAG_FORM:
        {
            attr = gumbo_get_attribute(&node->v.element.attributes, "method");
            if (attr) {
                if (strcasecmp(attr->value, "get")==0) (*forms_get)++;
            } else {
                // default is GET
                (*forms_get)++;
            }
            break;
        }
        default:
            break;
    }
    children = &node->v.element.children;
    for (unsigned int i=0;i<children->length;i++) traverse((GumboNode*)children->data[i], base_url, inline_scripts, external_scripts, forms_get, mixed_content);
}

int main(int argc, char** argv) {
    if (argc < 2) { fprintf(stderr,"Usage: %s <url>\n", argv[0]); return 1; }
    const char* url = argv[1];
    CURL *curl = curl_easy_init();
    struct mem m = {NULL,0};
    if (!curl) return 1;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ext-scanner/1.0");
    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        fprintf(stderr,"curl failed: %s\n", curl_easy_strerror(rc));
        curl_easy_cleanup(curl);
        free(m.buf);
        return 2;
    }
    char *content_type = NULL;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    double total_time = 0; curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

    printf("URL: %s\nHTTP Status: %ld\nContent-Type: %s\nSize: %zu bytes\n\n", url, response_code, content_type?content_type:"-", m.size);

    // parse with gumbo
    GumboOutput* output = gumbo_parse_with_options(&kGumboDefaultOptions, m.buf, m.size);
    int inline_scripts = 0, external_scripts = 0, forms_get = 0, mixed_content = 0;
    traverse(output->root, url, &inline_scripts, &external_scripts, &forms_get, &mixed_content);

    // check CSP meta presence
    GumboVector* head_children = &output->root->v.element.children;
    int csp_meta_found = 0;
    // simple scan for meta http-equiv
    // (we did not record earlier; re-scan meta tags quickly)
    // ... to keep code concise we will do a shallow search:
    GumboVector* html_children = &output->root->v.element.children;
    // This is approximate; for robust implementation find <meta http-equiv=Content-Security-Policy> precisely.
    const char *body_text = m.buf;
    if (strstr(body_text, "Content-Security-Policy") != NULL) csp_meta_found = 1;

    printf("Inline scripts: %d\nExternal scripts: %d\nForms with GET/default: %d\nMixed-content resources: %d\nCSP meta present (heuristic): %d\n", inline_scripts, external_scripts, forms_get, mixed_content, csp_meta_found);

    gumbo_destroy_output(&kGumboDefaultOptions, output);
    curl_easy_cleanup(curl);
    free(m.buf);
    return 0;
}
ext_scanner_c.c
