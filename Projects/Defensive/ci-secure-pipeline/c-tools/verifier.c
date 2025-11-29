#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>

#define MAX_BUFFER_SIZE 4096
#define MAX_CMD_SIZE 1024

// Exit codes
#define EXIT_SUCCESS 0
#define EXIT_WARNING 1
#define EXIT_FAILURE 2

// Function declarations
int verify_image_signature(const char *image_name);
int verify_attestation(const char *image_name);
int check_vulnerability_policy(const char *scan_results_path);
int parse_attestation_json(const char *json_file);
void log_info(const char *message);
void log_warning(const char *message);
void log_error(const char *message);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <image-name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *image_name = argv[1];
    int overall_status = EXIT_SUCCESS;

    log_info("Starting image verification process");

    // 1. Verify image signature
    if (verify_image_signature(image_name) != 0) {
        log_error("Image signature verification failed");
        overall_status = EXIT_FAILURE;
    } else {
        log_info("Image signature verification passed");
    }

    // 2. Verify attestations
    if (verify_attestation(image_name) != 0) {
        log_warning("Attestation verification failed or missing");
        if (overall_status == EXIT_SUCCESS) {
            overall_status = EXIT_WARNING;
        }
    } else {
        log_info("Attestation verification passed");
    }

    // 3. Check vulnerability policy (simplified)
    // In real implementation, this would fetch and check scan results
    const char *scan_file = "/tmp/scan-results.json";
    if (access(scan_file, F_OK) == 0) {
        if (check_vulnerability_policy(scan_file) != 0) {
            log_error("Vulnerability policy check failed");
            overall_status = EXIT_FAILURE;
        } else {
            log_info("Vulnerability policy check passed");
        }
    } else {
        log_warning("No scan results found for policy check");
    }

    // Final decision
    switch (overall_status) {
        case EXIT_SUCCESS:
            log_info("All verification checks passed");
            break;
        case EXIT_WARNING:
            log_warning("Some non-critical verification checks failed");
            break;
        case EXIT_FAILURE:
            log_error("Critical verification checks failed - deployment blocked");
            break;
    }

    return overall_status;
}

int verify_image_signature(const char *image_name) {
    char command[MAX_CMD_SIZE];
    snprintf(command, sizeof(command), "cosign verify %s 2>/dev/null", image_name);
    
    log_info("Verifying image signature with cosign");
    int result = system(command);
    
    if (WIFEXITED(result)) {
        return WEXITSTATUS(result);
    }
    return EXIT_FAILURE;
}

int verify_attestation(const char *image_name) {
    char command[MAX_CMD_SIZE];
    snprintf(command, sizeof(command), 
             "cosign verify-attestation --type vuln %s 2>/dev/null", image_name);
    
    log_info("Verifying vulnerability attestation");
    int result = system(command);
    
    if (WIFEXITED(result)) {
        return WEXITSTATUS(result);
    }
    return EXIT_FAILURE;
}

int check_vulnerability_policy(const char *scan_results_path) {
    FILE *file = fopen(scan_results_path, "r");
    if (!file) {
        log_error("Failed to open scan results file");
        return EXIT_FAILURE;
    }

    char buffer[MAX_BUFFER_SIZE];
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, file);
    fclose(file);
    buffer[len] = '\0';

    json_error_t error;
    json_t *root = json_loads(buffer, 0, &error);
    if (!root) {
        log_error("Failed to parse JSON scan results");
        return EXIT_FAILURE;
    }

    // Simple policy: Fail on CRITICAL vulnerabilities
    json_t *results = json_object_get(root, "Results");
    if (!json_is_array(results)) {
        json_decref(root);
        return EXIT_SUCCESS; // No vulnerabilities found
    }

    size_t index;
    json_t *result;
    int critical_count = 0;

    json_array_foreach(results, index, result) {
        json_t *vulns = json_object_get(result, "Vulnerabilities");
        if (json_is_array(vulns)) {
            size_t vuln_index;
            json_t *vuln;
            
            json_array_foreach(vulns, vuln_index, vuln) {
                json_t *severity = json_object_get(vuln, "Severity");
                if (severity && json_is_string(severity)) {
                    const char *sev = json_string_value(severity);
                    if (strcmp(sev, "CRITICAL") == 0) {
                        critical_count++;
                        json_t *vuln_id = json_object_get(vuln, "VulnerabilityID");
                        if (vuln_id && json_is_string(vuln_id)) {
                            log_error(json_string_value(vuln_id));
                        }
                    }
                }
            }
        }
    }

    json_decref(root);

    if (critical_count > 0) {
        log_error("Policy violation: Critical vulnerabilities found");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void log_info(const char *message) {
    printf("[INFO] %s\n", message);
}

void log_warning(const char *message) {
    printf("[WARN] %s\n", message);
}

void log_error(const char *message) {
    fprintf(stderr, "[ERROR] %s\n", message);
}
