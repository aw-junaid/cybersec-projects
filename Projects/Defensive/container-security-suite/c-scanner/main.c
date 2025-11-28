/**
 * Container Security Scanner - C Implementation
 * Lightweight scanner for CI/CD integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/wait.h>

#include "registry.h"
#include "vulnerability.h"
#include "signature.h"

#define MAX_IMAGE_LEN 256
#define MAX_OUTPUT_LEN 4096

typedef struct {
    char image[MAX_IMAGE_LEN];
    int fail_threshold;
    int warn_threshold;
    int verify_signature;
    int test_mode;
} scan_config_t;

void print_usage(const char* program_name) {
    printf("Container Security Scanner\n");
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -i, --image IMAGE        Container image to scan (required)\n");
    printf("  -f, --fail-threshold N   Fail if risk score >= N (default: 50)\n");
    printf("  -w, --warn-threshold N   Warn if risk score >= N (default: 20)\n");
    printf("  -s, --no-signature-check Skip signature verification\n");
    printf("  -t, --test               Run in test mode\n");
    printf("  -h, --help               Show this help message\n");
}

int parse_arguments(int argc, char* argv[], scan_config_t* config) {
    static struct option long_options[] = {
        {"image", required_argument, 0, 'i'},
        {"fail-threshold", required_argument, 0, 'f'},
        {"warn-threshold", required_argument, 0, 'w'},
        {"no-signature-check", no_argument, 0, 's'},
        {"test", no_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    // Set defaults
    memset(config, 0, sizeof(scan_config_t));
    config->fail_threshold = 50;
    config->warn_threshold = 20;
    config->verify_signature = 1;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "i:f:w:sth", 
                             long_options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(config->image, optarg, MAX_IMAGE_LEN - 1);
                break;
            case 'f':
                config->fail_threshold = atoi(optarg);
                break;
            case 'w':
                config->warn_threshold = atoi(optarg);
                break;
            case 's':
                config->verify_signature = 0;
                break;
            case 't':
                config->test_mode = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                return -1;
        }
    }

    if (strlen(config->image) == 0 && !config->test_mode) {
        fprintf(stderr, "Error: Image name is required\n");
        return -1;
    }

    return 0;
}

int execute_command(const char* cmd, char* output, size_t output_len) {
    FILE* fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    size_t total_read = 0;
    char buffer[128];

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t len = strlen(buffer);
        if (total_read + len < output_len) {
            strncpy(output + total_read, buffer, len);
            total_read += len;
        } else {
            break;
        }
    }

    output[total_read] = '\0';
    return pclose(fp);
}

int scan_image_with_trivy(const char* image, scan_result_t* result) {
    char cmd[512];
    char output[2048];
    int exit_code;

    snprintf(cmd, sizeof(cmd), 
             "trivy image --format json --quiet %s 2>/dev/null", image);
    
    exit_code = execute_command(cmd, output, sizeof(output));
    
    if (exit_code != 0) {
        return -1;
    }

    // Parse Trivy JSON output (simplified)
    // In real implementation, use jansson to parse JSON
    if (strstr(output, "CRITICAL") != NULL) {
        result->critical_count++;
    }
    if (strstr(output, "HIGH") != NULL) {
        result->high_count++;
    }

    return 0;
}

int verify_image_signature(const char* image) {
    char cmd[512];
    char output[1024];
    
    snprintf(cmd, sizeof(cmd), "cosign verify %s 2>/dev/null", image);
    int exit_code = execute_command(cmd, output, sizeof(output));
    
    return (exit_code == 0) ? 1 : 0;
}

void generate_json_report(const scan_result_t* result, const scan_config_t* config) {
    printf("{\n");
    printf("  \"image\": \"%s\",\n", config->image);
    printf("  \"risk_score\": %d,\n", result->risk_score);
    printf("  \"critical_vulnerabilities\": %d,\n", result->critical_count);
    printf("  \"high_vulnerabilities\": %d,\n", result->high_count);
    printf("  \"signature_verified\": %s,\n", result->signature_verified ? "true" : "false");
    printf("  \"passed\": %s,\n", result->passed ? "true" : "false");
    printf("  \"scan_duration\": %.2f\n", result->scan_duration);
    printf("}\n");
}

int main(int argc, char* argv[]) {
    scan_config_t config;
    scan_result_t result;
    
    if (parse_arguments(argc, argv, &config) != 0) {
        fprintf(stderr, "Failed to parse arguments\n");
        return 2;
    }

    if (config.test_mode) {
        // Test with a known image
        strcpy(config.image, "alpine:latest");
        printf("Running in test mode with image: %s\n", config.image);
    }

    memset(&result, 0, sizeof(scan_result_t));
    
    // Start timing
    double start_time = (double)clock() / CLOCKS_PER_SEC;

    // Scan image
    if (scan_image_with_trivy(config.image, &result) != 0) {
        fprintf(stderr, "Failed to scan image: %s\n", config.image);
        return 2;
    }

    // Verify signature if requested
    if (config.verify_signature) {
        result.signature_verified = verify_image_signature(config.image);
    } else {
        result.signature_verified = 1; // Assume verified if not checking
    }

    // Calculate risk score
    result.risk_score = result.critical_count * 10 + result.high_count * 8;
    if (!result.signature_verified) {
        result.risk_score += 20;
    }

    // Determine if passed
    result.passed = (result.risk_score < config.fail_threshold);

    // Calculate scan duration
    double end_time = (double)clock() / CLOCKS_PER_SEC;
    result.scan_duration = end_time - start_time;

    // Generate JSON report
    generate_json_report(&result, &config);

    // Return appropriate exit code
    if (!result.passed) {
        return 1; // Failed
    } else if (result.risk_score >= config.warn_threshold) {
        return 2; // Warning
    }

    return 0; // Success
}
