#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>

#define MAX_LINE_LENGTH 1024
#define MAX_PATTERNS 10

typedef struct {
    char name[50];
    char pattern[100];
    char description[100];
} DetectionRule;

typedef struct {
    char filename[100];
    long size;
    time_t last_modified;
    int is_compromised;
} LogFileInfo;

void initialize_detection_rules(DetectionRule rules[]) {
    strcpy(rules[0].name, "timestamp_anomaly");
    strcpy(rules[0].pattern, "[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}");
    strcpy(rules[0].description, "Timestamp format validation");
    
    strcpy(rules[1].name, "suspicious_deletion");
    strcpy(rules[1].pattern, "rm.*log|truncate|delete.*log");
    strcpy(rules[1].description, "Log deletion commands");
    
    strcpy(rules[2].name, "base64_data");
    strcpy(rules[2].pattern, "[A-Za-z0-9+/]{20,}={0,2}");
    strcpy(rules[2].description, "Base64 encoded data");
}

int check_pattern(const char *line, const char *pattern) {
    // Simple pattern matching (in real implementation, use regex)
    return strstr(line, pattern) != NULL;
}

void analyze_log_file(const char *filename, DetectionRule rules[], int rule_count) {
    printf("Analyzing log file: %s\n", filename);
    
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("  [!] Cannot open file (may be deleted)\n");
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_number = 0;
    int suspicious_lines = 0;
    
    while (fgets(line, sizeof(line), file)) {
        line_number++;
        
        for (int i = 0; i < rule_count; i++) {
            if (check_pattern(line, rules[i].pattern)) {
                printf("  [!] Suspicious pattern detected at line %d\n", line_number);
                printf("      Rule: %s\n", rules[i].name);
                printf("      Description: %s\n", rules[i].description);
                printf("      Line: %.50s...\n", line);
                suspicious_lines++;
            }
        }
        
        // Check for other anomalies
        if (strlen(line) > 500) {
            printf("  [!] Excessively long line at line %d (possible log flooding)\n", line_number);
            suspicious_lines++;
        }
    }
    
    fclose(file);
    
    if (suspicious_lines == 0) {
        printf("  [✓] No obvious evasion patterns detected\n");
    } else {
        printf("  [!] Found %d suspicious lines\n", suspicious_lines);
    }
}

void demonstrate_evasion_techniques() {
    printf("\n=== LOG EVASION TECHNIQUES ===\n");
    
    printf("\n1. Log Deletion/Modification:\n");
    printf("   - rm /var/log/auth.log\n");
    printf("   - echo '' > /var/log/syslog\n");
    printf("   - shred -u logfile.log\n");
    
    printf("\n2. Timestamp Manipulation:\n");
    printf("   - touch -t 202301010000 logfile.log\n");
    printf("   - Using fake timestamps in log entries\n");
    
    printf("\n3. Data Obfuscation:\n");
    printf("   - Base64 encoding: echo 'secret' | base64\n");
    printf("   - Hex encoding: echo 'secret' | xxd -p\n");
    printf("   - ROT13 encoding: echo 'secret' | tr 'A-Za-z' 'N-ZA-Mn-za-m'\n");
    
    printf("\n4. Log Injection:\n");
    printf("   - Injecting false entries\n");
    printf("   - Log poisoning with malicious data\n");
    printf("   - Format string attacks\n");
    
    printf("\n5. Steganography:\n");
    printf("   - Hiding data in log whitespace\n");
    printf("   - Using unicode characters\n");
    printf("   - Zero-width characters\n");
}

void show_defense_techniques() {
    printf("\n=== DEFENSE TECHNIQUES ===\n");
    
    printf("\n1. Log Protection:\n");
    printf("   - Immutable log files (chattr +i)\n");
    printf("   - Proper file permissions\n");
    printf("   - Append-only logging\n");
    
    printf("\n2. Monitoring:\n");
    printf("   - Real-time log analysis\n");
    printf("   - File integrity monitoring\n");
    printf("   - Statistical anomaly detection\n");
    
    printf("\n3. Architecture:\n");
    printf("   - Centralized logging (SIEM)\n");
    printf("   - Remote syslog servers\n");
    printf("   - Write-once read-many (WORM) storage\n");
    
    printf("\n4. Detection Rules:\n");
    printf("   - Pattern matching for evasion techniques\n");
    printf("   - Behavioral analysis\n");
    printf("   - Machine learning anomaly detection\n");
}

void simulate_evasion_scenario() {
    printf("\n=== EVASION SCENARIO SIMULATION ===\n");
    
    // Create sample log files
    system("mkdir -p test_logs");
    system("echo '2024-01-01 10:00:00 sshd[1234]: Accepted password for user1' > test_logs/auth.log");
    system("echo '2024-01-01 10:01:00 kernel: System normal' > test_logs/system.log");
    
    // Initialize detection rules
    DetectionRule rules[MAX_PATTERNS];
    initialize_detection_rules(rules);
    int rule_count = 3;
    
    printf("\nPhase 1: Initial Analysis\n");
    analyze_log_file("test_logs/auth.log", rules, rule_count);
    analyze_log_file("test_logs/system.log", rules, rule_count);
    
    printf("\nPhase 2: Simulating Evasion\n");
    printf("[!] Simulating log deletion...\n");
    system("rm test_logs/system.log");
    
    printf("[!] Simulating log injection...\n");
    system("echo 'INJECTED: c2VjcmV0Cg==' >> test_logs/auth.log");  // Base64 encoded
    
    printf("\nPhase 3: Post-Evasion Analysis\n");
    analyze_log_file("test_logs/auth.log", rules, rule_count);
    analyze_log_file("test_logs/system.log", rules, rule_count);
    
    // Cleanup
    system("rm -rf test_logs");
}

int main() {
    printf("Log Evasion Simulator - Educational Tool\n");
    printf("========================================\n");
    printf("FOR AUTHORIZED SECURITY RESEARCH ONLY\n\n");
    
    simulate_evasion_scenario();
    demonstrate_evasion_techniques();
    show_defense_techniques();
    
    printf("\n=== LEGAL AND ETHICAL USAGE ===\n");
    printf("This tool is intended for:\n");
    printf("  ✅ Security education and awareness\n");
    printf("  ✅ Defensive security training\n");
    printf("  ✅ Security tool development\n");
    printf("  ✅ Authorized penetration testing\n");
    printf("\nProhibited uses:\n");
    printf("  ❌ Unauthorized system access\n");
    printf("  ❌ Malicious activity\n");
    printf("  ❌ Attacks without permission\n");
    
    return 0;
}
