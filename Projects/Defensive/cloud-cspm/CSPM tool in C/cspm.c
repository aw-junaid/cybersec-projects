#include "cspm.h"

// Simple CSPM implementation in C
// Note: This is a simplified version for demonstration

static CURL* curl_handle = NULL;
static security_rule_t rules[] = {
    {"PUBLIC_S3_BUCKET", "public-read-write", SEVERITY_HIGH, CATEGORY_STORAGE},
    {"OPEN_SECURITY_GROUP", "0.0.0.0/0", SEVERITY_HIGH, CATEGORY_NETWORK},
    {"NO_MFA", "Password.*MFA", SEVERITY_MEDIUM, CATEGORY_IAM},
    {"ADMIN_PRIVILEGES", "AdministratorAccess", SEVERITY_HIGH, CATEGORY_IAM},
    { "", "", SEVERITY_INFO, CATEGORY_MONITORING } // Sentinel
};

int cspm_init(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl_handle = curl_easy_init();
    
    if (!curl_handle) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return -1;
    }
    
    return 0;
}

void cspm_cleanup(void) {
    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
    }
    curl_global_cleanup();
}

scan_result_t* cspm_scan_aws(const char* profile) {
    scan_result_t* result = malloc(sizeof(scan_result_t));
    if (!result) {
        return NULL;
    }
    
    result->count = 0;
    result->overall_risk = 0.0;
    
    // Scan different AWS services
    aws_check_s3_buckets(result, profile);
    aws_check_iam_users(result, profile);
    aws_check_security_groups(result, profile);
    
    // Calculate overall risk
    if (result->count > 0) {
        double total_risk = 0.0;
        for (int i = 0; i < result->count; i++) {
            total_risk += result->findings[i].risk_score;
        }
        result->overall_risk = total_risk / result->count;
    }
    
    return result;
}

int aws_check_s3_buckets(scan_result_t* result, const char* profile) {
    // Simplified S3 bucket check
    // In real implementation, this would make AWS API calls
    
    // Example finding: public S3 bucket
    if (result->count < MAX_FINDINGS) {
        finding_t* finding = &result->findings[result->count];
        
        strncpy(finding->resource_id, "example-public-bucket", MAX_RESOURCE_ID);
        strncpy(finding->resource_type, "S3_Bucket", 64);
        strncpy(finding->provider, "aws", 32);
        strncpy(finding->description, "S3 bucket with public read access", MAX_DESCRIPTION);
        
        finding->severity = SEVERITY_HIGH;
        finding->category = CATEGORY_STORAGE;
        finding->risk_score = cspm_calculate_risk_score(finding);
        finding->timestamp = time(NULL);
        
        result->count++;
    }
    
    return 0;
}

int aws_check_iam_users(scan_result_t* result, const char* profile) {
    // Simplified IAM user check
    
    // Example finding: IAM user without MFA
    if (result->count < MAX_FINDINGS) {
        finding_t* finding = &result->findings[result->count];
        
        strncpy(finding->resource_id, "example-user", MAX_RESOURCE_ID);
        strncpy(finding->resource_type, "IAM_User", 64);
        strncpy(finding->provider, "aws", 32);
        strncpy(finding->description, "IAM user without multi-factor authentication", MAX_DESCRIPTION);
        
        finding->severity = SEVERITY_MEDIUM;
        finding->category = CATEGORY_IAM;
        finding->risk_score = cspm_calculate_risk_score(finding);
        finding->timestamp = time(NULL);
        
        result->count++;
    }
    
    // Example finding: Overly permissive IAM policy
    if (result->count < MAX_FINDINGS) {
        finding_t* finding = &result->findings[result->count];
        
        strncpy(finding->resource_id, "admin-policy", MAX_RESOURCE_ID);
        strncpy(finding->resource_type, "IAM_Policy", 64);
        strncpy(finding->provider, "aws", 32);
        strncpy(finding->description, "IAM policy with administrator privileges", MAX_DESCRIPTION);
        
        finding->severity = SEVERITY_HIGH;
        finding->category = CATEGORY_IAM;
        finding->risk_score = cspm_calculate_risk_score(finding);
        finding->timestamp = time(NULL);
        
        result->count++;
    }
    
    return 0;
}

int aws_check_security_groups(scan_result_t* result, const char* profile) {
    // Simplified security group check
    
    // Example finding: Open SSH security group
    if (result->count < MAX_FINDINGS) {
        finding_t* finding = &result->findings[result->count];
        
        strncpy(finding->resource_id, "sg-12345678", MAX_RESOURCE_ID);
        strncpy(finding->resource_type, "Security_Group", 64);
        strncpy(finding->provider, "aws", 32);
        strncpy(finding->description, "Security group allows SSH from anywhere (0.0.0.0/0)", MAX_DESCRIPTION);
        
        finding->severity = SEVERITY_HIGH;
        finding->category = CATEGORY_NETWORK;
        finding->risk_score = cspm_calculate_risk_score(finding);
        finding->timestamp = time(NULL);
        
        result->count++;
    }
    
    return 0;
}

double cspm_calculate_risk_score(finding_t* finding) {
    double base_score = 0.0;
    
    // Base score from severity
    switch (finding->severity) {
        case SEVERITY_CRITICAL: base_score = 9.5; break;
        case SEVERITY_HIGH: base_score = 8.0; break;
        case SEVERITY_MEDIUM: base_score = 5.0; break;
        case SEVERITY_LOW: base_score = 2.0; break;
        case SEVERITY_INFO: base_score = 0.5; break;
    }
    
    // Adjust based on category
    switch (finding->category) {
        case CATEGORY_IAM: base_score *= 1.2; break;
        case CATEGORY_NETWORK: base_score *= 1.1; break;
        case CATEGORY_STORAGE: base_score *= 1.0; break;
        case CATEGORY_COMPUTE: base_score *= 1.0; break;
        case CATEGORY_MONITORING: base_score *= 0.8; break;
    }
    
    return base_score > 10.0 ? 10.0 : base_score;
}

severity_t cspm_determine_severity(double risk_score) {
    if (risk_score >= 9.0) return SEVERITY_CRITICAL;
    if (risk_score >= 7.0) return SEVERITY_HIGH;
    if (risk_score >= 5.0) return SEVERITY_MEDIUM;
    if (risk_score >= 3.0) return SEVERITY_LOW;
    return SEVERITY_INFO;
}

void cspm_generate_json_report(scan_result_t* result, const char* filename) {
    json_t* root = json_object();
    json_t* findings_array = json_array();
    
    // Add metadata
    json_object_set_new(root, "generated_at", json_string(ctime(&(time_t){time(NULL)})));
    json_object_set_new(root, "total_findings", json_integer(result->count));
    json_object_set_new(root, "overall_risk_score", json_real(result->overall_risk));
    
    // Add findings
    for (int i = 0; i < result->count; i++) {
        finding_t* finding = &result->findings[i];
        json_t* finding_obj = json_object();
        
        json_object_set_new(finding_obj, "resource_id", json_string(finding->resource_id));
        json_object_set_new(finding_obj, "resource_type", json_string(finding->resource_type));
        json_object_set_new(finding_obj, "provider", json_string(finding->provider));
        json_object_set_new(finding_obj, "description", json_string(finding->description));
        json_object_set_new(finding_obj, "risk_score", json_real(finding->risk_score));
        json_object_set_new(finding_obj, "timestamp", json_string(ctime(&finding->timestamp)));
        
        // Convert severity enum to string
        const char* severity_str = "INFO";
        switch (finding->severity) {
            case SEVERITY_CRITICAL: severity_str = "CRITICAL"; break;
            case SEVERITY_HIGH: severity_str = "HIGH"; break;
            case SEVERITY_MEDIUM: severity_str = "MEDIUM"; break;
            case SEVERITY_LOW: severity_str = "LOW"; break;
            case SEVERITY_INFO: severity_str = "INFO"; break;
        }
        json_object_set_new(finding_obj, "severity", json_string(severity_str));
        
        json_array_append_new(findings_array, finding_obj);
    }
    
    json_object_set_new(root, "findings", findings_array);
    
    // Write to file
    FILE* fp = fopen(filename, "w");
    if (fp) {
        json_dumpf(root, fp, JSON_INDENT(2));
        fclose(fp);
        printf("JSON report written to %s\n", filename);
    } else {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
    }
    
    json_decref(root);
}

void cspm_generate_cli_report(scan_result_t* result) {
    printf("\n=== CLOUD SECURITY POSTURE MANAGEMENT REPORT ===\n");
    printf("Generated: %s", ctime(&(time_t){time(NULL)}));
    printf("Total Findings: %d\n", result->count);
    printf("Overall Risk Score: %.2f/10.0\n\n", result->overall_risk);
    
    printf("DETAILED FINDINGS:\n");
    printf("==================\n");
    
    for (int i = 0; i < result->count; i++) {
        finding_t* finding = &result->findings[i];
        
        const char* severity_str = "INFO";
        switch (finding->severity) {
            case SEVERITY_CRITICAL: severity_str = "CRITICAL"; break;
            case SEVERITY_HIGH: severity_str = "HIGH"; break;
            case SEVERITY_MEDIUM: severity_str = "MEDIUM"; break;
            case SEVERITY_LOW: severity_str = "LOW"; break;
            case SEVERITY_INFO: severity_str = "INFO"; break;
        }
        
        printf("\n%d. [%s] %s\n", i + 1, severity_str, finding->resource_type);
        printf("   Resource: %s\n", finding->resource_id);
        printf("   Provider: %s\n", finding->provider);
        printf("   Description: %s\n", finding->description);
        printf("   Risk Score: %.2f\n", finding->risk_score);
    }
    
    printf("\n=== END OF REPORT ===\n");
}

// CURL write callback function
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    char* data = (char*)userp;
    
    memcpy(data, contents, realsize);
    return realsize;
}
