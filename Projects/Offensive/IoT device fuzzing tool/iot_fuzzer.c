#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#define MAX_PAYLOAD_SIZE 65536
#define MAX_FUZZ_CASES 1000
#define SOCKET_TIMEOUT 5

typedef struct {
    char *payload;
    size_t length;
    char *protocol;
    int case_number;
} FuzzCase;

typedef struct {
    char target_ip[16];
    int target_port;
    FuzzCase *fuzz_cases;
    int case_count;
    int current_case;
    int crashes_detected;
    int is_running;
} FuzzerState;

// Utility functions
void generate_fuzz_payload(char *base_payload, size_t base_len, char **fuzz_payload, size_t *fuzz_len) {
    // Simple mutation: duplicate, truncate, or add random data
    int mutation_type = rand() % 3;
    
    switch (mutation_type) {
        case 0: // Duplicate
            *fuzz_len = base_len * 2;
            *fuzz_payload = malloc(*fuzz_len);
            memcpy(*fuzz_payload, base_payload, base_len);
            memcpy(*fuzz_payload + base_len, base_payload, base_len);
            break;
            
        case 1: // Truncate
            *fuzz_len = base_len / 2;
            if (*fuzz_len < 1) *fuzz_len = 1;
            *fuzz_payload = malloc(*fuzz_len);
            memcpy(*fuzz_payload, base_payload, *fuzz_len);
            break;
            
        case 2: // Add random
            *fuzz_len = base_len + (rand() % 100) + 1;
            *fuzz_payload = malloc(*fuzz_len);
            memcpy(*fuzz_payload, base_payload, base_len);
            for (size_t i = base_len; i < *fuzz_len; i++) {
                (*fuzz_payload)[i] = rand() % 256;
            }
            break;
    }
}

void generate_http_fuzz_cases(FuzzCase *cases, int *count) {
    char *base_requests[] = {
        "GET / HTTP/1.1\r\nHost: target\r\n\r\n",
        "POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 5\r\n\r\nadmin",
        "GET /config HTTP/1.1\r\nHost: target\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n",
    };
    
    int base_count = sizeof(base_requests) / sizeof(base_requests[0]);
    
    for (int i = 0; i < base_count && *count < MAX_FUZZ_CASES; i++) {
        for (int j = 0; j < 10 && *count < MAX_FUZZ_CASES; j++) {
            char *fuzz_payload;
            size_t fuzz_len;
            
            generate_fuzz_payload(base_requests[i], strlen(base_requests[i]), 
                                &fuzz_payload, &fuzz_len);
            
            cases[*count].payload = fuzz_payload;
            cases[*count].length = fuzz_len;
            cases[*count].protocol = "HTTP";
            cases[*count].case_number = *count;
            
            (*count)++;
        }
    }
}

int send_fuzz_packet(const char *target_ip, int target_port, 
                     const char *payload, size_t payload_len, 
                     int use_udp) {
    int sockfd;
    struct sockaddr_in target_addr;
    
    if (use_udp) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }
    
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = SOCKET_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Configure target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &target_addr.sin_addr);
    
    if (!use_udp) {
        // TCP connection
        if (connect(sockfd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            close(sockfd);
            return -1;
        }
    }
    
    int result = 0;
    
    if (use_udp) {
        // UDP send
        if (sendto(sockfd, payload, payload_len, 0, 
                  (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            result = -1;
        }
    } else {
        // TCP send
        if (send(sockfd, payload, payload_len, 0) < 0) {
            result = -1;
        }
    }
    
    // Try to receive response (for detection)
    if (result == 0) {
        char buffer[1024];
        int bytes_received;
        
        if (use_udp) {
            socklen_t addr_len = sizeof(target_addr);
            bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                     (struct sockaddr*)&target_addr, &addr_len);
        } else {
            bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
        }
        
        if (bytes_received < 0) {
            // Timeout or error - might indicate crash
            result = 1; // Potential crash
        }
    }
    
    close(sockfd);
    return result;
}

void* fuzzer_worker(void *arg) {
    FuzzerState *state = (FuzzerState*)arg;
    
    while (state->is_running && state->current_case < state->case_count) {
        int case_idx = state->current_case++;
        FuzzCase *fuzz_case = &state->fuzz_cases[case_idx];
        
        printf("[%s] Case %d: %zu bytes\n", 
               fuzz_case->protocol, case_idx, fuzz_case->length);
        
        int use_udp = (strcmp(fuzz_case->protocol, "UDP") == 0 || 
                       strcmp(fuzz_case->protocol, "CoAP") == 0);
        
        int result = send_fuzz_packet(state->target_ip, state->target_port,
                                    fuzz_case->payload, fuzz_case->length, use_udp);
        
        if (result == 1) {
            printf("  [POTENTIAL CRASH] No response received\n");
            state->crashes_detected++;
        } else if (result == -1) {
            printf("  [SEND ERROR] Connection failed\n");
        }
        
        // Small delay to avoid overwhelming the target
        usleep(100000); // 100ms
    }
    
    return NULL;
}

void start_fuzzing(FuzzerState *state, int thread_count) {
    printf("Starting fuzzing with %d threads\n", thread_count);
    printf("Target: %s:%d\n", state->target_ip, state->target_port);
    printf("Total test cases: %d\n", state->case_count);
    printf("====================================\n");
    
    state->is_running = 1;
    state->current_case = 0;
    state->crashes_detected = 0;
    
    pthread_t threads[thread_count];
    
    // Create worker threads
    for (int i = 0; i < thread_count; i++) {
        pthread_create(&threads[i], NULL, fuzzer_worker, state);
    }
    
    // Wait for completion
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\nFuzzing completed!\n");
    printf("Crashes detected: %d\n", state->crashes_detected);
}

void cleanup_fuzzer(FuzzerState *state) {
    for (int i = 0; i < state->case_count; i++) {
        free(state->fuzz_cases[i].payload);
    }
    free(state->fuzz_cases);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target_ip> <target_port> [thread_count]\n", argv[0]);
        printf("Example: %s 192.168.1.100 80 4\n");
        return 1;
    }
    
    srand(time(NULL));
    
    FuzzerState state;
    strncpy(state.target_ip, argv[1], sizeof(state.target_ip) - 1);
    state.target_port = atoi(argv[2]);
    int thread_count = argc > 3 ? atoi(argv[3]) : 4;
    
    // Initialize fuzz cases
    state.fuzz_cases = malloc(MAX_FUZZ_CASES * sizeof(FuzzCase));
    state.case_count = 0;
    
    // Generate HTTP fuzz cases
    generate_http_fuzz_cases(state.fuzz_cases, &state.case_count);
    
    printf("IoT Device Fuzzer - C Implementation\n");
    printf("Generated %d test cases\n", state.case_count);
    
    // Start fuzzing
    start_fuzzing(&state, thread_count);
    
    // Cleanup
    cleanup_fuzzer(&state);
    
    return 0;
}
