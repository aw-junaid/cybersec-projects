// honeypot_c.c
// Simple threaded TCP honeypot in C
// Compile: gcc -o honeypot_c honeypot_c.c -lpthread
// Run: sudo ./honeypot_c

#define _POSIX_C_SOURCE 200809L  // Enable POSIX features for modern C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

// ===== CONFIGURATION =====
#define MAX_LOG 5*1024*1024      // Maximum log size before rotation (5MB)
#define LOGFILE "honeypot_c.log" // Log file name
#define BUFSIZE 4096             // Buffer size for reading data

// Structure to define listener configuration
struct listener {
    int port;               // Port to listen on
    const char *banner;     // Banner to send when connection established
};

// Structure to pass connection information to handler threads
struct conninfo {
    int fd;                 // Socket file descriptor
    struct sockaddr_in addr;// Client address information
    int port;               // Local port we're listening on
    const char *banner;     // Banner for this port
};

/**
 * Check if log file needs rotation and rotate if necessary
 * Creates backup with timestamp if log exceeds MAX_LOG
 */
void rotate_log_if_needed() {
    FILE *f = fopen(LOGFILE, "r");
    if (!f) return;  // If file doesn't exist, nothing to rotate
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fclose(f);
    
    if (size > MAX_LOG) {
        char bak[256];
        time_t t = time(NULL);
        struct tm *tm = gmtime(&t);
        // Create backup filename with timestamp
        strftime(bak, sizeof(bak), LOGFILE".%Y%m%dT%H%M%SZ", tm);
        rename(LOGFILE, bak);  // Rotate the log file
    }
}

/**
 * Create hexdump of binary data for logging
 * @param f: File pointer to write output
 * @param buf: Buffer containing data to dump
 * @param len: Length of data in buffer
 */
void hexdump_to_file(FILE *f, const unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 16) {
        // Print offset
        fprintf(f, "%08zx  ", i);
        
        // Print hex values
        size_t j;
        for (j = 0; j < 16; ++j) {
            if (i + j < len) 
                fprintf(f, "%02x ", buf[i+j]);
            else 
                fprintf(f, "   ");  // Padding for incomplete lines
        }
        
        fprintf(f, " ");  // Space between hex and ASCII
        
        // Print ASCII representation
        for (j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = buf[i+j];
            // Print printable characters, others as dots
            fprintf(f, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        fprintf(f, "\n");
    }
}

/**
 * Handle individual client connection (runs in separate thread)
 * @param arg: Pointer to conninfo structure
 * @return: NULL (thread exit)
 */
void *conn_handler(void *arg) {
    struct conninfo *ci = (struct conninfo *)arg;
    char addrstr[INET_ADDRSTRLEN];  // Buffer for IP address string
    
    // Convert client IP address to string
    inet_ntop(AF_INET, &(ci->addr.sin_addr), addrstr, sizeof(addrstr));
    int port = ntohs(ci->addr.sin_port);  // Convert port to host byte order
    time_t now = time(NULL);  // Current timestamp

    // Rotate log if needed before processing connection
    rotate_log_if_needed();
    
    // Open log file for appending
    FILE *f = fopen(LOGFILE, "a");
    if (!f) {
        perror("open log");
        close(ci->fd);
        free(ci);
        return NULL;
    }

    // Log connection start information
    fprintf(f, "=== CONNECTION START ===\n");
    fprintf(f, "time: %s", asctime(gmtime(&now)));  // UTC time
    fprintf(f, "remote: %s:%d\n", addrstr, port);   // Client IP:port
    fprintf(f, "local_port: %d\n", ci->port);       // Local port

    // Send banner to make service appear legitimate
    if (ci->banner) {
        send(ci->fd, ci->banner, strlen(ci->banner), 0);
    }

    // Set receive timeout to avoid hanging (8 seconds)
    struct timeval tv;
    tv.tv_sec = 8;
    tv.tv_usec = 0;
    setsockopt(ci->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Buffer for reading data
    unsigned char buf[BUFSIZE];
    ssize_t r;
    size_t total = 0;
    unsigned char *collected = NULL;  // Dynamic buffer for all received data
    
    // Read all data from client until timeout or connection close
    while ((r = recv(ci->fd, buf, sizeof(buf), 0)) > 0) {
        // Append received data to collected buffer
        unsigned char *n = realloc(collected, total + r);
        if (!n) break;  // Stop if realloc fails
        collected = n;
        memcpy(collected + total, buf, r);
        total += r;
        if (total > 200000) break; // Limit total collected data to 200KB
    }

    // Log received data (if any)
    if (total > 0) {
        fprintf(f, "--- RAW DATA (%zu bytes) ---\n", total);
        hexdump_to_file(f, collected, total);  // Log hexdump
    } else {
        fprintf(f, "--- NO DATA RECEIVED ---\n");
    }

    // Log connection closure
    fprintf(f, "time_closed: %s", asctime(gmtime(&now)));
    fprintf(f, "=== CONNECTION END ===\n\n");
    fclose(f);

    // Cleanup
    if (collected) free(collected);
    close(ci->fd);  // Close socket
    free(ci);       // Free connection info structure
    return NULL;
}

/**
 * Start listening on specified port and handle connections
 * @param port: Port number to listen on
 * @param banner: Banner string to send to clients
 * @return: 0 on success, -1 on error
 */
int start_listener_thread(int port, const char *banner) {
    // Create TCP socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { 
        perror("socket"); 
        return -1; 
    }
    
    // Set socket option to reuse address (avoid "address in use" errors)
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address structure
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;           // IPv4
    sa.sin_addr.s_addr = INADDR_ANY;   // Listen on all interfaces
    sa.sin_port = htons(port);         // Port in network byte order

    // Bind socket to address
    if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    // Start listening for connections (backlog of 16)
    if (listen(sock, 16) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }

    printf("[+] Listening on 0.0.0.0:%d\n", port);
    
    // Main accept loop - handles incoming connections
    while (1) {
        // Allocate connection info structure
        struct conninfo *ci = malloc(sizeof(*ci));
        if (!ci) continue;
        
        socklen_t len = sizeof(ci->addr);
        // Accept incoming connection
        ci->fd = accept(sock, (struct sockaddr*)&ci->addr, &len);
        if (ci->fd < 0) {
            perror("accept");
            free(ci);
            continue;  // Continue on accept errors
        }
        
        ci->port = port;
        ci->banner = banner;

        // Create detached thread to handle connection
        pthread_t t;
        pthread_create(&t, NULL, conn_handler, ci);
        pthread_detach(t);  // Thread cleans up automatically when done
    }
    
    // Never reached in normal operation
    close(sock);
    return 0;
}

/**
 * Main function - starts honeypot listeners
 */
int main(void) {
    // Hard-coded listeners same as Python for parity
    struct listener listens[] = {
        {2222, "SSH-2.0-OpenSSH_7.9p1 Kali-C\n"},           // SSH imitation
        {8080, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"}  // HTTP imitation
    };
    
    int num_listeners = sizeof(listens)/sizeof(listens[0]);
    
    // For simplicity run listeners in child processes (one per port)
    for (int i = 0; i < num_listeners; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            // child process: run listener
            start_listener_thread(listens[i].port, listens[i].banner);
            exit(0);  // Exit child process when listener stops
        } else if (pid < 0) {
            perror("fork");
        }
    }

    // Parent process: wait indefinitely
    printf("Honeypot (C) running. Logs -> %s\n", LOGFILE);
    printf("Listening on ports: ");
    for (int i = 0; i < num_listeners; ++i) {
        printf("%d ", listens[i].port);
    }
    printf("\nPress Ctrl+C to stop\n");
    
    while (1) sleep(60);  // Sleep forever (main process does nothing)
    
    return 0;
}
