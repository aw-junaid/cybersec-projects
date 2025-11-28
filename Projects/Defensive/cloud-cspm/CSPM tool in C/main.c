#include "cspm.h"

int main(int argc, char* argv[]) {
    printf("Cloud CSPM Tool - C Version\n");
    printf("===========================\n");
    
    // Initialize CSPM
    if (cspm_init() != 0) {
        fprintf(stderr, "Failed to initialize CSPM\n");
        return 1;
    }
    
    // Scan AWS (simplified - using default profile)
    printf("Scanning AWS resources...\n");
    scan_result_t* aws_results = cspm_scan_aws("default");
    
    if (aws_results) {
        // Generate reports
        cspm_generate_json_report(aws_results, "security_report.json");
        cspm_generate_cli_report(aws_results);
        
        // Cleanup
        free(aws_results);
    }
    
    // Cleanup CSPM
    cspm_cleanup();
    
    printf("Scan completed.\n");
    return 0;
}
