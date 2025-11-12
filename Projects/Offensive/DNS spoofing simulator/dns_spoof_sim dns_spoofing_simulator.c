#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_DOMAINS 100
#define MAX_DOMAIN_LENGTH 100
#define MAX_IP_LENGTH 16
#define MAX_LOG_ENTRIES 1000

typedef struct {
    char domain[MAX_DOMAIN_LENGTH];
    char legitimate_ip[MAX_IP_LENGTH];
    char spoofed_ip[MAX_IP_LENGTH];
    int spoof_count;
} DNSRecord;

typedef struct {
    char timestamp[20];
    char domain[MAX_DOMAIN_LENGTH];
    char response_ip[MAX_IP_LENGTH];
    char client_ip[MAX_IP_LENGTH];
    int is_spoofed;
    char detection_type[50];
} DNSLogEntry;

typedef struct {
    DNSRecord records[MAX_DOMAINS];
    DNSLogEntry log[MAX_LOG_ENTRIES];
    int record_count;
    int log_count;
    int simulation_running;
} DNSSimulator;

// Utility functions
void get_current_timestamp(char *buffer) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", t);
}

void initialize_simulator(DNSSimulator *sim) {
    sim->record_count = 0;
    sim->log_count = 0;
    sim->simulation_running = 0;
    
    // Initialize with some default records
    add_dns_record(sim, "example.com", "93.184.216.34", "192.168.1.100");
    add_dns_record(sim, "google.com", "142.250.190.78", "192.168.1.101");
    add_dns_record(sim, "facebook.com", "157.240.229.35", "192.168.1.102");
}

int add_dns_record(DNSSimulator *sim, const char *domain, 
                   const char *legit_ip, const char *spoof_ip) {
    if (sim->record_count >= MAX_DOMAINS) {
        return 0;
    }
    
    DNSRecord *record = &sim->records[sim->record_count];
    strncpy(record->domain, domain, MAX_DOMAIN_LENGTH - 1);
    strncpy(record->legitimate_ip, legit_ip, MAX_IP_LENGTH - 1);
    strncpy(record->spoofed_ip, spoof_ip, MAX_IP_LENGTH - 1);
    record->spoof_count = 0;
    
    sim->record_count++;
    return 1;
}

DNSRecord* find_dns_record(DNSSimulator *sim, const char *domain) {
    for (int i = 0; i < sim->record_count; i++) {
        if (strcmp(sim->records[i].domain, domain) == 0) {
            return &sim->records[i];
        }
    }
    return NULL;
}

void log_dns_query(DNSSimulator *sim, const char *domain, 
                   const char *response_ip, const char *client_ip, 
                   int is_spoofed, const char *detection_type) {
    if (sim->log_count >= MAX_LOG_ENTRIES) {
        return;
    }
    
    DNSLogEntry *entry = &sim->log[sim->log_count];
    get_current_timestamp(entry->timestamp);
    strncpy(entry->domain, domain, MAX_DOMAIN_LENGTH - 1);
    strncpy(entry->response_ip, response_ip, MAX_IP_LENGTH - 1);
    strncpy(entry->client_ip, client_ip, MAX_IP_LENGTH - 1);
    entry->is_spoofed = is_spoofed;
    strncpy(entry->detection_type, detection_type, 49);
    
    sim->log_count++;
}

// DNS Spoofing simulation functions
char* spoof_dns_response(DNSSimulator *sim, const char *domain, const char *client_ip) {
    DNSRecord *record = find_dns_record(sim, domain);
    if (record != NULL) {
        record->spoof_count++;
        log_dns_query(sim, domain, record->spoofed_ip, client_ip, 1, "SPOOFED_RESPONSE");
        
        printf("[SPOOF] %s -> %s for client %s\n", 
               domain, record->spoofed_ip, client_ip);
        
        return record->spoofed_ip;
    }
    return NULL;
}

char* legitimate_dns_response(DNSSimulator *sim, const char *domain, const char *client_ip) {
    DNSRecord *record = find_dns_record(sim, domain);
    if (record != NULL) {
        log_dns_query(sim, domain, record->legitimate_ip, client_ip, 0, "LEGITIMATE_RESPONSE");
        
        printf("[LEGIT] %s -> %s for client %s\n", 
               domain, record->legitimate_ip, client_ip);
        
        return record->legitimate_ip;
    }
    return NULL;
}

// Detection functions
int detect_dns_spoofing(DNSSimulator *sim, const char *domain, 
                        const char *response_ip, const char *client_ip) {
    DNSRecord *record = find_dns_record(sim, domain);
    if (record == NULL) {
        return 0;
    }
    
    int detection_flags = 0;
    
    // Check if response matches spoofed IP
    if (strcmp(response_ip, record->spoofed_ip) == 0) {
        detection_flags |= 1; // KNOWN_SPOOFED_IP
    }
    
    // Check for private IP in response (simplified)
    if (strncmp(response_ip, "192.168.", 8) == 0 || 
        strncmp(response_ip, "10.", 3) == 0) {
        detection_flags |= 2; // PRIVATE_IP_RESPONSE
    }
    
    // Check for rapid queries from same client (simplified)
    int recent_queries = 0;
    for (int i = sim->log_count - 1; i >= 0 && i > sim->log_count - 10; i--) {
        if (strcmp(sim->log[i].client_ip, client_ip) == 0) {
            recent_queries++;
        }
    }
    
    if (recent_queries > 5) {
        detection_flags |= 4; // RAPID_QUERIES
    }
    
    if (detection_flags > 0) {
        char detection_type[50] = "DETECTION_ALERT";
        log_dns_query(sim, domain, response_ip, client_ip, 1, detection_type);
        
        printf("[ALERT] Potential DNS spoofing detected!\n");
        printf("        Domain: %s\n", domain);
        printf("        Response IP: %s\n", response_ip);
        printf("        Client IP: %s\n", client_ip);
        printf("        Detection Flags: %d\n", detection_flags);
        
        return 1;
    }
    
    return 0;
}

// Simulation thread function
void* simulation_thread(void *arg) {
    DNSSimulator *sim = (DNSSimulator*)arg;
    int query_id = 0;
    
    while (sim->simulation_running) {
        // Simulate DNS queries from different clients
        char client_ip[16];
        snprintf(client_ip, sizeof(client_ip), "192.168.1.%d", (query_id % 10) + 1);
        
        // Alternate between legitimate and spoofed queries
        if (query_id % 3 == 0) {
            // Spoofed query
            int record_idx = query_id % sim->record_count;
            spoof_dns_response(sim, sim->records[record_idx].domain, client_ip);
        } else {
            // Legitimate query
            int record_idx = query_id % sim->record_count;
            char *response = legitimate_dns_response(sim, sim->records[record_idx].domain, client_ip);
            detect_dns_spoofing(sim, sim->records[record_idx].domain, response, client_ip);
        }
        
        query_id++;
        sleep(1); // Simulate query interval
    }
    
    return NULL;
}

void generate_report(DNSSimulator *sim) {
    printf("\n============================================================\n");
    printf("DNS SPOOFING SIMULATION REPORT\n");
    printf("============================================================\n");
    
    int total_queries = sim->log_count;
    int spoofed_attempts = 0;
    int detections = 0;
    
    for (int i = 0; i < sim->log_count; i++) {
        if (sim->log[i].is_spoofed) {
            spoofed_attempts++;
        }
        if (strstr(sim->log[i].detection_type, "DETECTION") != NULL) {
            detections++;
        }
    }
    
    printf("Total queries simulated: %d\n", total_queries);
    printf("Spoofing attempts: %d\n", spoofed_attempts);
    printf("Detection alerts: %d\n", detections);
    
    printf("\nRecent activity (last 5 entries):\n");
    for (int i = sim->log_count - 5; i < sim->log_count; i++) {
        if (i >= 0) {
            printf("  [%s] %s: %s -> %s\n", 
                   sim->log[i].timestamp,
                   sim->log[i].detection_type,
                   sim->log[i].domain,
                   sim->log[i].response_ip);
        }
    }
}

int main() {
    DNSSimulator simulator;
    initialize_simulator(&simulator);
    
    printf("DNS Spoofing Simulator - Educational Tool\n");
    printf("Starting simulation for 30 seconds...\n");
    
    // Start simulation
    simulator.simulation_running = 1;
    pthread_t sim_thread;
    pthread_create(&sim_thread, NULL, simulation_thread, &simulator);
    
    // Run for 30 seconds
    sleep(30);
    simulator.simulation_running = 0;
    pthread_join(sim_thread, NULL);
    
    // Generate report
    generate_report(&simulator);
    
    return 0;
}
