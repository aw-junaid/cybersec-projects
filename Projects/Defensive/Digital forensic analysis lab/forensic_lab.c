/**
 * Digital Forensic Analysis Lab - C Implementation
 * Compile: gcc -o forensic_lab forensic_lab.c -lm -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/md5.h>

#define MAX_PROCESSES 100
#define MAX_CONNECTIONS 50
#define MAX_STRINGS 1000
#define MAX_ARTIFACTS 500
#define MAX_TIMELINE 200
#define STRING_LENGTH 256

typedef struct {
    int pid;
    char name[STRING_LENGTH];
    int parent_pid;
    char path[STRING_LENGTH];
    char command_line[STRING_LENGTH];
    char start_time[STRING_LENGTH];
} ProcessInfo;

typedef struct {
    char protocol[10];
    char local_address[16];
    int local_port;
    char remote_address[16];
    int remote_port;
    char state[20];
    int pid;
} NetworkConnection;

typedef struct {
    char offset[20];
    char string[STRING_LENGTH];
    int length;
} ExtractedString;

typedef struct {
    char timestamp[STRING_LENGTH];
    char event[STRING_LENGTH];
    char source[STRING_LENGTH];
    char artifact[STRING_LENGTH];
} TimelineEvent;

typedef struct {
    char type[50];
    char indicator[STRING_LENGTH];
    char confidence[20];
} MalwareIndicator;

typedef struct {
    ProcessInfo processes[MAX_PROCESSES];
    int process_count;
    NetworkConnection connections[MAX_CONNECTIONS];
    int connection_count;
    ExtractedString strings[MAX_STRINGS];
    int string_count;
    MalwareIndicator indicators[50];
    int indicator_count;
} MemoryAnalysis;

typedef struct {
    char filename[STRING_LENGTH];
    char original_path[STRING_LENGTH];
    char deleted_time[STRING_LENGTH];
    int recoverable;
    char size[20];
} DeletedFile;

typedef struct {
    TimelineEvent events[MAX_TIMELINE];
    int event_count;
    DeletedFile deleted_files[100];
    int deleted_file_count;
} DiskAnalysis;

void calculate_md5(const char* filename, char* output) {
    FILE* file = fopen(filename, "rb");
    if(!file) {
        strcpy(output, "Error");
        return;
    }
    
    MD5_CTX md5Context;
    MD5_Init(&md5Context);
    
    unsigned char buffer[1024];
    int bytesRead;
    while((bytesRead = fread(buffer, 1, 1024, file)) != 0) {
        MD5_Update(&md5Context, buffer, bytesRead);
    }
    
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5_Final(digest, &md5Context);
    
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", digest[i]);
    }
    output[MD5_DIGEST_LENGTH * 2] = '\0';
    
    fclose(file);
}

void analyze_memory_dump(const char* memory_dump, MemoryAnalysis* analysis) {
    printf("[*] Analyzing memory dump: %s\n", memory_dump);
    
    // Simulate process extraction
    analysis->process_count = 4;
    analysis->processes[0] = (ProcessInfo){4, "System", 0, "C:\\Windows\\System32\\ntoskrnl.exe", "", "2024-01-15T08:00:00"};
    analysis->processes[1] = (ProcessInfo){264, "csrss.exe", 4, "C:\\Windows\\System32\\csrss.exe", "csrss.exe ObjectDirectory=\\Windows", "2024-01-15T08:00:01"};
    analysis->processes[2] = (ProcessInfo){1884, "notepad.exe", 264, "C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\secret.txt", "2024-01-15T10:30:15"};
    analysis->processes[3] = (ProcessInfo){1922, "suspicious.exe", 1884, "C:\\Temp\\suspicious.exe", "suspicious.exe -stealth", "2024-01-15T10:31:22"};
    
    // Simulate network connections
    analysis->connection_count = 2;
    analysis->connections[0] = (NetworkConnection){"TCP", "192.168.1.100", 49215, "45.33.32.156", 443, "ESTABLISHED", 1922};
    analysis->connections[1] = (NetworkConnection){"UDP", "192.168.1.100", 53, "8.8.8.8", 53, "LISTENING", 984};
    
    // Simulate string extraction
    analysis->string_count = 5;
    analysis->strings[0] = (ExtractedString){"0x1000", "This is a test string", 21};
    analysis->strings[1] = (ExtractedString){"0x2000", "C:\\Temp\\suspicious.exe", 22};
    analysis->strings[2] = (ExtractedString){"0x3000", "http://malicious.com", 20};
    analysis->strings[3] = (ExtractedString){"0x4000", "MZ header", 9};
    analysis->strings[4] = (ExtractedString){"0x5000", "secret password", 15};
    
    // Simulate malware indicators
    analysis->indicator_count = 4;
    analysis->indicators[0] = (MalwareIndicator){"Process", "suspicious.exe", "High"};
    analysis->indicators[1] = (MalwareIndicator){"IP", "45.33.32.156", "Medium"};
    analysis->indicators[2] = (MalwareIndicator){"String", "MZ header", "Low"};
    analysis->indicators[3] = (MalwareIndicator){"Network", "Suspicious port", "Medium"};
}

void analyze_disk_image(const char* disk_image, DiskAnalysis* analysis) {
    printf("[*] Analyzing disk image: %s\n", disk_image);
    
    // Simulate timeline creation
    analysis->event_count = 4;
    analysis->events[0] = (TimelineEvent){"2024-01-15T08:00:00", "System Boot", "System", "Event Log"};
    analysis->events[1] = (TimelineEvent){"2024-01-15T10:30:15", "Notepad started", "Process", "Prefetch"};
    analysis->events[2] = (TimelineEvent){"2024-01-15T10:31:22", "Suspicious process started", "Process", "Memory"};
    analysis->events[3] = (TimelineEvent){"2024-01-15T10:35:00", "File deleted", "File System", "MFT"};
    
    // Simulate deleted file recovery
    analysis->deleted_file_count = 2;
    analysis->deleted_files[0] = (DeletedFile){"secret_document.pdf", "C:\\Users\\John\\Documents\\", "2024-01-15T10:35:00", 1, "2.5MB"};
    analysis->deleted_files[1] = (DeletedFile){"malware.exe", "C:\\Temp\\", "2024-01-15T10:32:00", 0, "1.2MB"};
}

void print_memory_analysis(const MemoryAnalysis* analysis, const char* output_file) {
    FILE* output = stdout;
    if(output_file) {
        output = fopen(output_file, "w");
        if(!output) {
            printf("[-] Cannot open output file: %s\n", output_file);
            return;
        }
    }
    
    fprintf(output, "=== MEMORY ANALYSIS REPORT ===\n\n");
    
    fprintf(output, "PROCESSES:\n");
    for(int i = 0; i < analysis->process_count; i++) {
        fprintf(output, "  PID: %d, Name: %s, Parent: %d\n", 
                analysis->processes[i].pid, 
                analysis->processes[i].name,
                analysis->processes[i].parent_pid);
        fprintf(output, "    Path: %s\n", analysis->processes[i].path);
        fprintf(output, "    CmdLine: %s\n", analysis->processes[i].command_line);
        fprintf(output, "    Start: %s\n\n", analysis->processes[i].start_time);
    }
    
    fprintf(output, "NETWORK CONNECTIONS:\n");
    for(int i = 0; i < analysis->connection_count; i++) {
        fprintf(output, "  %s %s:%d -> %s:%d (%s) PID: %d\n",
                analysis->connections[i].protocol,
                analysis->connections[i].local_address,
                analysis->connections[i].local_port,
                analysis->connections[i].remote_address,
                analysis->connections[i].remote_port,
                analysis->connections[i].state,
                analysis->connections[i].pid);
    }
    
    fprintf(output, "\nMALWARE INDICATORS:\n");
    for(int i = 0; i < analysis->indicator_count; i++) {
        fprintf(output, "  %s: %s (Confidence: %s)\n",
                analysis->indicators[i].type,
                analysis->indicators[i].indicator,
                analysis->indicators[i].confidence);
    }
    
    if(output_file) {
        fclose(output);
        printf("[+] Memory analysis saved to: %s\n", output_file);
    }
}

void print_disk_analysis(const DiskAnalysis* analysis, const char* output_file) {
    FILE* output = stdout;
    if(output_file) {
        output = fopen(output_file, "w");
        if(!output) {
            printf("[-] Cannot open output file: %s\n", output_file);
            return;
        }
    }
    
    fprintf(output, "=== DISK ANALYSIS REPORT ===\n\n");
    
    fprintf(output, "TIMELINE:\n");
    for(int i = 0; i < analysis->event_count; i++) {
        fprintf(output, "  %s: %s (%s - %s)\n",
                analysis->events[i].timestamp,
                analysis->events[i].event,
                analysis->events[i].source,
                analysis->events[i].artifact);
    }
    
    fprintf(output, "\nDELETED FILES:\n");
    for(int i = 0; i < analysis->deleted_file_count; i++) {
        fprintf(output, "  %s -> %s\n", 
                analysis->deleted_files[i].filename,
                analysis->deleted_files[i].original_path);
        fprintf(output, "    Deleted: %s, Recoverable: %s, Size: %s\n",
                analysis->deleted_files[i].deleted_time,
                analysis->deleted_files[i].recoverable ? "Yes" : "No",
                analysis->deleted_files[i].size);
    }
    
    if(output_file) {
        fclose(output);
        printf("[+] Disk analysis saved to: %s\n", output_file);
    }
}

void generate_forensic_report(const MemoryAnalysis* memory, const DiskAnalysis* disk, const char* output_file) {
    FILE* report = fopen(output_file, "w");
    if(!report) {
        printf("[-] Cannot create report file: %s\n", output_file);
        return;
    }
    
    time_t now = time(NULL);
    fprintf(report, "=== DIGITAL FORENSIC ANALYSIS REPORT ===\n\n");
    fprintf(report, "Generated: %s", ctime(&now));
    fprintf(report, "Case ID: CASE-2024-001\n");
    fprintf(report, "Analyst: Forensic Investigator\n\n");
    
    fprintf(report, "EXECUTIVE SUMMARY:\n");
    fprintf(report, "Found %d suspicious processes and %d malware indicators in memory.\n", 
            memory->process_count, memory->indicator_count);
    fprintf(report, "Timeline analysis revealed %d key events.\n\n", disk->event_count);
    
    fprintf(report, "KEY FINDINGS:\n");
    fprintf(report, "- Suspicious process: suspicious.exe (PID: 1922)\n");
    fprintf(report, "- Network connections to known malicious IP: 45.33.32.156\n");
    fprintf(report, "- Evidence of file deletion and data exfiltration attempts\n\n");
    
    fprintf(report, "RECOMMENDATIONS:\n");
    fprintf(report, "1. Isolate affected systems immediately\n");
    fprintf(report, "2. Conduct deeper memory analysis\n");
    fprintf(report, "3. Review firewall and network monitoring rules\n");
    fprintf(report, "4. Implement enhanced endpoint protection\n");
    
    fclose(report);
    printf("[+] Forensic report generated: %s\n", output_file);
}

int main(int argc, char* argv[]) {
    if(argc < 3) {
        printf("Digital Forensic Analysis Lab\n");
        printf("Usage:\n");
        printf("  Memory Analysis: %s memory <memory_dump> [output_file]\n", argv[0]);
        printf("  Disk Analysis: %s disk <disk_image> [output_file]\n", argv[0]);
        printf("  Full Report: %s report <memory_dump> <disk_image> <output_report>\n", argv[0]);
        return 1;
    }
    
    if(strcmp(argv[1], "memory") == 0) {
        MemoryAnalysis analysis;
        analyze_memory_dump(argv[2], &analysis);
        print_memory_analysis(&analysis, argc > 3 ? argv[3] : NULL);
    }
    else if(strcmp(argv[1], "disk") == 0) {
        DiskAnalysis analysis;
        analyze_disk_image(argv[2], &analysis);
        print_disk_analysis(&analysis, argc > 3 ? argv[3] : NULL);
    }
    else if(strcmp(argv[1], "report") == 0 && argc >= 5) {
        MemoryAnalysis memory_analysis;
        DiskAnalysis disk_analysis;
        
        analyze_memory_dump(argv[2], &memory_analysis);
        analyze_disk_image(argv[3], &disk_analysis);
        generate_forensic_report(&memory_analysis, &disk_analysis, argv[4]);
    }
    else {
        printf("Invalid command or arguments\n");
        return 1;
    }
    
    return 0;
}
