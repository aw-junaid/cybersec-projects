#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <fcntl.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define MAX_PATH 4096
#define MAX_PROCESSES 1024
#define MAX_SIGNATURES 100

typedef struct {
    char name[256];
    char type[50];
    char confidence[20];
    char details[512];
} detection_t;

typedef struct {
    detection_t detections[1000];
    int count;
} scan_results_t;

// Rootkit signatures
const char* rootkit_signatures[] = {
    "adore", "adore-ng", "beastkit", "diamon", "fu", "kbeast",
    "knark", "mood-nt", "phide", "sebek", "suckit", "w32.spybot",
    "hidden", "stealth", "rootkit", "rkdetect", "syscall_hook"
};

// Function prototypes
void scan_processes(scan_results_t* results);
void scan_filesystem(scan_results_t* results);
void check_integrity(scan_results_t* results);
void cross_view_analysis(scan_results_t* results);
void add_detection(scan_results_t* results, const char* name, const char* type, 
                   const char* confidence, const char* details);
void print_results(scan_results_t* results);

int main() {
    printf("Rootkit Detection Toolkit - C Core Engine\n");
    printf("=========================================\n\n");
    
    scan_results_t results = {0};
    
    printf("Starting rootkit detection scan...\n\n");
    
    // Perform various detection methods
    cross_view_analysis(&results);
    scan_processes(&results);
    scan_filesystem(&results);
    check_integrity(&results);
    
    // Print results
    print_results(&results);
    
    printf("\nScan complete. Found %d potential issues.\n", results.count);
    
    return 0;
}

void cross_view_analysis(scan_results_t* results) {
    printf("Performing cross-view analysis...\n");
    
    // Compare process list from /proc with other methods
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return;
    }
    
    struct dirent* entry;
    int proc_count = 0;
    int hidden_count = 0;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR && atoi(entry->d_name) > 0) {
            proc_count++;
            
            // Check if process is visible via other means
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
            
            FILE* stat_file = fopen(path, "r");
            if (!stat_file) {
                hidden_count++;
                add_detection(results, "Hidden Process", "cross_view", "high", 
                             entry->d_name);
            } else {
                fclose(stat_file);
            }
        }
    }
    
    closedir(proc_dir);
    
    printf("  Scanned %d processes, found %d hidden\n", proc_count, hidden_count);
}

void scan_processes(scan_results_t* results) {
    printf("Scanning running processes...\n");
    
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;
    
    struct dirent* entry;
    int suspicious_count = 0;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR && atoi(entry->d_name) > 0) {
            char exe_path[MAX_PATH];
            char cmdline_path[MAX_PATH];
            char buffer[MAX_PATH];
            
            // Check executable path
            snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", entry->d_name);
            ssize_t len = readlink(exe_path, buffer, sizeof(buffer)-1);
            if (len != -1) {
                buffer[len] = '\0';
                
                // Check for suspicious locations
                if (strstr(buffer, "/tmp/") || strstr(buffer, "/dev/shm/")) {
                    suspicious_count++;
                    add_detection(results, buffer, "suspicious_location", "medium", 
                                 entry->d_name);
                }
                
                // Check against signatures
                for (int i = 0; i < sizeof(rootkit_signatures)/sizeof(rootkit_signatures[0]); i++) {
                    if (strstr(buffer, rootkit_signatures[i])) {
                        add_detection(results, buffer, "signature_match", "high", 
                                     rootkit_signatures[i]);
                    }
                }
            }
            
            // Check command line
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
            FILE* cmdline_file = fopen(cmdline_path, "r");
            if (cmdline_file) {
                if (fgets(buffer, sizeof(buffer), cmdline_file)) {
                    for (int i = 0; i < sizeof(rootkit_signatures)/sizeof(rootkit_signatures[0]); i++) {
                        if (strstr(buffer, rootkit_signatures[i])) {
                            add_detection(results, buffer, "cmdline_signature", "medium", 
                                         rootkit_signatures[i]);
                        }
                    }
                }
                fclose(cmdline_file);
            }
        }
    }
    
    closedir(proc_dir);
    printf("  Found %d suspicious processes\n", suspicious_count);
}

void scan_filesystem(scan_results_t* results) {
    printf("Scanning filesystem for rootkit artifacts...\n");
    
    const char* suspicious_dirs[] = {
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/tmp", "/var/tmp", "/dev/shm"
    };
    
    int found_count = 0;
    
    for (int i = 0; i < sizeof(suspicious_dirs)/sizeof(suspicious_dirs[0]); i++) {
        DIR* dir = opendir(suspicious_dirs[i]);
        if (!dir) continue;
        
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG || entry->d_type == DT_LNK) {
                char full_path[MAX_PATH];
                snprintf(full_path, sizeof(full_path), "%s/%s", 
                         suspicious_dirs[i], entry->d_name);
                
                // Check against signatures
                for (int j = 0; j < sizeof(rootkit_signatures)/sizeof(rootkit_signatures[0]); j++) {
                    if (strstr(entry->d_name, rootkit_signatures[j])) {
                        found_count++;
                        add_detection(results, full_path, "file_signature", "medium", 
                                     rootkit_signatures[j]);
                    }
                }
                
                // Check for hidden files starting with '.'
                if (entry->d_name[0] == '.' && strcmp(entry->d_name, ".") != 0 && 
                    strcmp(entry->d_name, "..") != 0) {
                    add_detection(results, full_path, "hidden_file", "low", 
                                 "File starts with dot");
                }
            }
        }
        
        closedir(dir);
    }
    
    printf("  Found %d suspicious files\n", found_count);
}

void check_integrity(scan_results_t* results) {
    printf("Checking system integrity...\n");
    
    // Critical system files to check
    const char* critical_files[] = {
        "/bin/ls", "/bin/ps", "/bin/netstat", "/bin/ss",
        "/usr/bin/top", "/usr/bin/htop", "/sbin/ifconfig"
    };
    
    int checked_count = 0;
    int suspicious_count = 0;
    
    for (int i = 0; i < sizeof(critical_files)/sizeof(critical_files[0]); i++) {
        struct stat file_stat;
        
        if (stat(critical_files[i], &file_stat) == 0) {
            checked_count++;
            
            // Check file permissions (should not be world-writable)
            if (file_stat.st_mode & S_IWOTH) {
                suspicious_count++;
                add_detection(results, critical_files[i], "world_writable", "high", 
                             "Critical system file is world writable");
            }
            
            // Check file size (basic sanity check)
            if (file_stat.st_size < 1024 || file_stat.st_size > 50*1024*1024) {
                suspicious_count++;
                add_detection(results, critical_files[i], "suspicious_size", "medium", 
                             "File size appears abnormal");
            }
            
            // Check ownership
            if (file_stat.st_uid == 0) {
                // Root owned - this is normal for system files
            } else {
                suspicious_count++;
                add_detection(results, critical_files[i], "suspicious_owner", "medium", 
                             "System file not owned by root");
            }
        }
    }
    
    printf("  Checked %d files, found %d integrity issues\n", checked_count, suspicious_count);
}

void add_detection(scan_results_t* results, const char* name, const char* type, 
                   const char* confidence, const char* details) {
    if (results->count >= 1000) return;
    
    detection_t* det = &results->detections[results->count];
    
    strncpy(det->name, name, sizeof(det->name)-1);
    strncpy(det->type, type, sizeof(det->type)-1);
    strncpy(det->confidence, confidence, sizeof(det->confidence)-1);
    strncpy(det->details, details, sizeof(det->details)-1);
    
    results->count++;
}

void print_results(scan_results_t* results) {
    printf("\n=== SCAN RESULTS ===\n");
    
    if (results->count == 0) {
        printf("No rootkit activity detected.\n");
        return;
    }
    
    // Group by confidence level
    int high_count = 0, medium_count = 0, low_count = 0;
    
    for (int i = 0; i < results->count; i++) {
        detection_t* det = &results->detections[i];
        
        if (strcmp(det->confidence, "high") == 0) high_count++;
        else if (strcmp(det->confidence, "medium") == 0) medium_count++;
        else low_count++;
    }
    
    printf("High confidence: %d\n", high_count);
    printf("Medium confidence: %d\n", medium_count);
    printf("Low confidence: %d\n", low_count);
    
    // Print high confidence findings
    if (high_count > 0) {
        printf("\nHIGH CONFIDENCE FINDINGS:\n");
        for (int i = 0; i < results->count; i++) {
            detection_t* det = &results->detections[i];
            if (strcmp(det->confidence, "high") == 0) {
                printf("  [%s] %s\n", det->type, det->name);
                printf("      Details: %s\n", det->details);
            }
        }
    }
}
