/**
 * Registry interaction functions
 */

#include "registry.h"
#include <curl/curl.h>
#include <jansson.h>
#include <string.h>
#include <stdio.h>

struct memory_struct {
    char* memory;
    size_t size;
};

static size_t write_memory_callback(void* contents, size_t size, 
                                   size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_struct* mem = (struct memory_struct*)userp;

    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int fetch_image_manifest(const char* image, char** manifest_json) {
    CURL* curl;
    CURLcode res;
    struct memory_struct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        char url[512];
        // Construct registry API URL (simplified)
        snprintf(url, sizeof(url), 
                "https://registry.hub.docker.com/v2/library/%s/manifests/latest",
                image);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "container-scanner/1.0");

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return -1;
        }

        curl_easy_cleanup(curl);
        
        *manifest_json = chunk.memory;
        return 0;
    }

    curl_global_cleanup();
    free(chunk.memory);
    return -1;
}

int parse_manifest_layers(const char* manifest_json, char*** layers, int* layer_count) {
    json_error_t error;
    json_t* root = json_loads(manifest_json, 0, &error);
    
    if (!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        return -1;
    }

    json_t* fs_layers = json_object_get(root, "fsLayers");
    if (!json_is_array(fs_layers)) {
        json_decref(root);
        return -1;
    }

    *layer_count = json_array_size(fs_layers);
    *layers = malloc(*layer_count * sizeof(char*));

    for (int i = 0; i < *layer_count; i++) {
        json_t* layer = json_array_get(fs_layers, i);
        json_t* blob_sum = json_object_get(layer, "blobSum");
        
        if (json_is_string(blob_sum)) {
            const char* digest = json_string_value(blob_sum);
            (*layers)[i] = strdup(digest);
        }
    }

    json_decref(root);
    return 0;
}
