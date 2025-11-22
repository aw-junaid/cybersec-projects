#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>

#define MAX_LINE_LENGTH 1024
#define MAX_VULNERABILITIES 100

typedef struct {
    char type[50];
    char severity[20];
    int line;
    char description[256];
    char exploit[256];
} Vulnerability;

typedef struct {
    Vulnerability vulnerabilities[MAX_VULNERABILITIES];
    int count;
} AuditResult;

void initialize_audit_result(AuditResult *result) {
    result->count = 0;
}

void add_vulnerability(AuditResult *result, const char *type, const char *severity, 
                      int line, const char *description, const char *exploit) {
    if (result->count < MAX_VULNERABILITIES) {
        Vulnerability *vuln = &result->vulnerabilities[result->count];
        strncpy(vuln->type, type, sizeof(vuln->type) - 1);
        strncpy(vuln->severity, severity, sizeof(vuln->severity) - 1);
        vuln->line = line;
        strncpy(vuln->description, description, sizeof(vuln->description) - 1);
        strncpy(vuln->exploit, exploit, sizeof(vuln->exploit) - 1);
        result->count++;
    }
}

int pattern_matches(const char *line, const char *pattern) {
    regex_t regex;
    int ret;
    
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        return 0;
    }
    
    ret = regexec(&regex, line, 0, NULL, 0);
    regfree(&regex);
    
    return ret == 0;
}

void detect_reentrancy(AuditResult *result, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_num = 1;
    const char *patterns[] = {
        "\\.call\\.value.*\\(\\)",
        "\\.send\\(",
        "\\.transfer\\(",
        "callcode\\(",
        "delegatecall\\(",
        NULL
    };
    
    while (fgets(line, sizeof(line), file)) {
        for (int i = 0; patterns[i] != NULL; i++) {
            if (pattern_matches(line, patterns[i])) {
                add_vulnerability(result, "REENTRANCY", "HIGH", line_num,
                                "Potential reentrancy vulnerability detected",
                                "Attackers can recursively call functions before state updates");
            }
        }
        line_num++;
    }
    
    fclose(file);
}

void detect_integer_issues(AuditResult *result, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_num = 1;
    int has_safemath = 0;
    
    // First pass: check for SafeMath
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "SafeMath") || strstr(line, "safemath")) {
            has_safemath = 1;
            break;
        }
    }
    
    rewind(file);
    line_num = 1;
    
    if (!has_safemath) {
        add_vulnerability(result, "NO_SAFEMATH", "MEDIUM", 1,
                         "SafeMath library not detected",
                         "Arithmetic operations may be vulnerable to overflows/underflows");
    }
    
    // Second pass: check arithmetic operations
    const char *arithmetic_patterns[] = {
        ".*\\+.*",
        ".*-.*",
        ".*\\*.*",
        ".*/.*",
        NULL
    };
    
    while (fgets(line, sizeof(line), file)) {
        for (int i = 0; arithmetic_patterns[i] != NULL; i++) {
            if (pattern_matches(line, arithmetic_patterns[i]) && 
                !strstr(line, "SafeMath") && 
                (strstr(line, "uint") || strstr(line, "int"))) {
                add_vulnerability(result, "ARITHMETIC_ISSUE", "HIGH", line_num,
                                "Potential integer overflow/underflow detected",
                                "Use SafeMath for arithmetic operations");
                break;
            }
        }
        line_num++;
    }
    
    fclose(file);
}

void detect_access_control_issues(AuditResult *result, const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open file");
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    int line_num = 1;
    int in_function = 0;
    char current_function[100] = "";
    
    const char *access_controls[] = {"onlyOwner", "require", "assert", "modifier", NULL};
    
    while (fgets(line, sizeof(line), file)) {
        // Check for function start
        if (strstr(line, "function") && strstr(line, "public") || strstr(line, "external")) {
            in_function = 1;
            strncpy(current_function, line, sizeof(current_function) - 1);
            
            // Check if function has access controls in the same line
            int has_control = 0;
            for (int i = 0; access_controls[i] != NULL; i++) {
                if (strstr(line, access_controls[i])) {
                    has_control = 1;
                    break;
                }
            }
            
            if (!has_control && !strstr(line, "constructor") && !strstr(line, "fallback")) {
                add_vulnerability(result, "ACCESS_CONTROL", "MEDIUM", line_num,
                                "Public/external function without access controls",
                                "Unauthorized users may call sensitive functions");
            }
        }
        
        line_num++;
    }
    
    fclose(file);
}

void generate_report(AuditResult *result, const char *filename) {
    printf("\n===============================================\n");
    printf("SMART CONTRACT SECURITY AUDIT REPORT\n");
    printf("===============================================\n");
    printf("Target: %s\n", filename);
    printf("Total Vulnerabilities: %d\n", result->count);
    
    int critical = 0, high = 0, medium = 0, low = 0;
    for (int i = 0; i < result->count; i++) {
        if (strcmp(result->vulnerabilities[i].severity, "CRITICAL") == 0) critical++;
        else if (strcmp(result->vulnerabilities[i].severity, "HIGH") == 0) high++;
        else if (strcmp(result->vulnerabilities[i].severity, "MEDIUM") == 0) medium++;
        else if (strcmp(result->vulnerabilities[i].severity, "LOW") == 0) low++;
    }
    
    printf("Critical: %d\n", critical);
    printf("High: %d\n", high);
    printf("Medium: %d\n", medium);
    printf("Low: %d\n", low);
    
    printf("\nDETAILED FINDINGS:\n");
    printf("-----------------------------------------------\n");
    
    for (int i = 0; i < result->count; i++) {
        Vulnerability *vuln = &result->vulnerabilities[i];
        printf("\n[%s] %s\n", vuln->severity, vuln->type);
        printf("Line %d: %s\n", vuln->line, vuln->description);
        printf("Exploit: %s\n", vuln->exploit);
    }
    
    printf("\n===============================================\n");
    printf("AUDIT COMPLETE\n");
    printf("===============================================\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <solidity_file>\n", argv[0]);
        return 1;
    }
    
    AuditResult result;
    initialize_audit_result(&result);
    
    printf("[*] Starting smart contract security audit...\n");
    printf("[*] Target: %s\n", argv[1]);
    
    detect_reentrancy(&result, argv[1]);
    detect_integer_issues(&result, argv[1]);
    detect_access_control_issues(&result, argv[1]);
    
    generate_report(&result, argv[1]);
    
    return 0;
}
