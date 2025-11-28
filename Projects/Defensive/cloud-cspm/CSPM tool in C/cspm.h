#ifndef CSPM_H
#define CSPM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <time.h>

#define MAX_FINDINGS 1000
#define MAX_RULE_LENGTH 256
#define MAX_RESOURCE_ID 128
#define MAX_DESCRIPTION 512

typedef enum {
    SEVERITY_CRITICAL = 4,
    SEVERITY_HIGH = 3,
    SEVERITY_MEDIUM = 2,
    SEVERITY_LOW = 1,
    SEVERITY_INFO = 0
} severity_t;

typedef enum {
    CATEGORY_IAM,
    CATEGORY_NETWORK,
    CATEGORY_STORAGE,
    CATEGORY_COMPUTE,
    CATEGORY_MONITORING
} category_t;

typedef struct {
    char resource_id[MAX_RESOURCE_ID];
    char resource_type[64];
    char provider[32];
    char description[MAX_DESCRIPTION];
    severity_t severity;
    category_t category;
    double risk_score;
    time_t timestamp;
} finding_t;

typedef struct {
    finding_t findings[MAX_FINDINGS];
    int count;
    double overall_risk;
} scan_result_t;

typedef struct {
    char name[MAX_RULE_LENGTH];
    char pattern[MAX_RULE_LENGTH];
    severity_t severity;
    category_t category;
} security_rule_t;

// Core functions
int cspm_init(void);
void cspm_cleanup(void);
scan_result_t* cspm_scan_aws(const char* profile);
scan_result_t* cspm_scan_azure(const char* subscription_id);
scan_result_t* cspm_scan_gcp(const char* project_id);

// Utility functions
void cspm_generate_json_report(scan_result_t* result, const char* filename);
void cspm_generate_cli_report(scan_result_t* result);
double cspm_calculate_risk_score(finding_t* finding);
severity_t cspm_determine_severity(double risk_score);

// AWS specific functions
int aws_check_s3_buckets(scan_result_t* result, const char* profile);
int aws_check_iam_users(scan_result_t* result, const char* profile);
int aws_check_security_groups(scan_result_t* result, const char* profile);

// HTTP and JSON helpers
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);
json_t* http_get_json(const char* url, const char* auth_header);
char* aws_sign_request(const char* service, const char* region, const char* access_key, const char* secret_key);

#endif
