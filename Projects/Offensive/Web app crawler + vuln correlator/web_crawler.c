#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <pthread.h>
#include <regex.h>

#define MAX_URLS 10000
#define MAX_URL_LENGTH 2048
#define MAX_THREADS 10
#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

typedef struct {
    char url[MAX_URL_LENGTH];
    int depth;
} URLNode;

typedef struct {
    URLNode urls[MAX_URLS];
    int front;
    int rear;
    int count;
    pthread_mutex_t lock;
} URLQueue;

typedef struct {
    char **visited_urls;
    int visited_count;
    pthread_mutex_t visited_lock;
} CrawlerState;

// Queue operations
void init_queue(URLQueue *queue) {
    queue->front = 0;
    queue->rear = -1;
    queue->count = 0;
    pthread_mutex_init(&queue->lock, NULL);
}

void enqueue(URLQueue *queue, const char *url, int depth) {
    pthread_mutex_lock(&queue->lock);
    
    if (queue->count < MAX_URLS) {
        queue->rear = (queue->rear + 1) % MAX_URLS;
        strncpy(queue->urls[queue->rear].url, url, MAX_URL_LENGTH - 1);
        queue->urls[queue->rear].depth = depth;
        queue->count++;
    }
    
    pthread_mutex_unlock(&queue->lock);
}

int dequeue(URLQueue *queue, URLNode *node) {
    pthread_mutex_lock(&queue->lock);
    
    if (queue->count == 0) {
        pthread_mutex_unlock(&queue->lock);
        return 0;
    }
    
    *node = queue->urls[queue->front];
    queue->front = (queue->front + 1) % MAX_URLS;
    queue->count--;
    
    pthread_mutex_unlock(&queue->lock);
    return 1;
}

// CURL write callback
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    char **response = (char**)userdata;
    
    *response = realloc(*response, strlen(*response) + total_size + 1);
    strncat(*response, ptr, total_size);
    
    return total_size;
}

// Extract URLs from HTML content
void extract_urls(const char *html, const char *base_url, URLQueue *queue, int current_depth) {
    regex_t regex;
    regmatch_t matches[2];
    const char *pattern = "href=[\"']([^\"'#]+)[\"']";
    
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
        return;
    }
    
    const char *cursor = html;
    while (regexec(&regex, cursor, 2, matches, 0) == 0) {
        // Extract URL
        int url_length = matches[1].rm_eo - matches[1].rm_so;
        char extracted_url[2048];
        strncpy(extracted_url, cursor + matches[1].rm_so, url_length);
        extracted_url[url_length] = '\0';
        
        // Normalize URL (simplified)
        char full_url[2048];
        if (strstr(extracted_url, "http") == extracted_url) {
            strcpy(full_url, extracted_url);
        } else {
            // Relative URL
            strcpy(full_url, base_url);
            strcat(full_url, extracted_url);
        }
        
        // Add to queue
        if (current_depth < 3) { // Limit depth
            enqueue(queue, full_url, current_depth + 1);
        }
        
        cursor += matches[0].rm_eo;
    }
    
    regfree(&regex);
}

// Check if URL was already visited
int is_visited(CrawlerState *state, const char *url) {
    pthread_mutex_lock(&state->visited_lock);
    
    for (int i = 0; i < state->visited_count; i++) {
        if (strcmp(state->visited_urls[i], url) == 0) {
            pthread_mutex_unlock(&state->visited_lock);
            return 1;
        }
    }
    
    pthread_mutex_unlock(&state->visited_lock);
    return 0;
}

// Mark URL as visited
void mark_visited(CrawlerState *state, const char *url) {
    pthread_mutex_lock(&state->visited_lock);
    
    state->visited_urls[state->visited_count] = malloc(strlen(url) + 1);
    strcpy(state->visited_urls[state->visited_count], url);
    state->visited_count++;
    
    pthread_mutex_unlock(&state->visited_lock);
}

// Worker thread function
void* crawl_worker(void *arg) {
    URLQueue *queue = ((void**)arg)[0];
    CrawlerState *state = ((void**)arg)[1];
    
    CURL *curl = curl_easy_init();
    if (!curl) {
        return NULL;
    }
    
    URLNode current;
    while (dequeue(queue, &current)) {
        if (is_visited(state, current.url)) {
            continue;
        }
        
        printf("Crawling: %s (Depth: %d)\n", current.url, current.depth);
        mark_visited(state, current.url);
        
        char *response = malloc(1);
        response[0] = '\0';
        
        curl_easy_setopt(curl, CURLOPT_URL, current.url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        
        CURLcode res = curl_easy_perform(curl);
        
        if (res == CURLE_OK) {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code == 200) {
                // Extract URLs from response
                extract_urls(response, current.url, queue, current.depth);
            }
        }
        
        free(response);
    }
    
    curl_easy_cleanup(curl);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <starting_url>\n", argv[0]);
        return 1;
    }
    
    printf("Basic Web Crawler - C Implementation\n");
    printf("Starting URL: %s\n", argv[1]);
    
    // Initialize components
    URLQueue queue;
    init_queue(&queue);
    
    CrawlerState state;
    state.visited_urls = malloc(MAX_URLS * sizeof(char*));
    state.visited_count = 0;
    pthread_mutex_init(&state.visited_lock, NULL);
    
    // Add starting URL
    enqueue(&queue, argv[1], 0);
    
    // Create worker threads
    pthread_t threads[MAX_THREADS];
    void *worker_args[2] = { &queue, &state };
    
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_create(&threads[i], NULL, crawl_worker, worker_args);
    }
    
    // Wait for threads to complete
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Print results
    printf("\nCrawling completed!\n");
    printf("Visited %d URLs\n", state.visited_count);
    
    // Cleanup
    for (int i = 0; i < state.visited_count; i++) {
        free(state.visited_urls[i]);
    }
    free(state.visited_urls);
    pthread_mutex_destroy(&state.visited_lock);
    pthread_mutex_destroy(&queue.lock);
    
    curl_global_cleanup();
    
    return 0;
}web_crawler.c
