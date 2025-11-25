/**
 * Snort/Suricata IDS Setup - C Implementation
 * Basic configuration generator and rule manager
 * Compile: gcc -o ids_manager ids_manager.c -lconfig
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>

#define MAX_LINE_LENGTH 1024
#define MAX_RULES 1000
#define CONFIG_DIR "/etc/ids"

typedef struct {
    char sid[20];
    char message[256];
    char protocol[10];
    char source_ip[50];
    char dest_ip[50];
    int enabled;
} IDSRule;

typedef struct {
    char home_net[50];
    char external_net[50];
    char interface[20];
    char log_dir[100];
    int max_rules;
} IDSConfig;

void create_directory(const char* path) {
    struct stat st = {0};
    if(stat(path, &st) == -1) {
        mkdir(path, 0755);
        printf("[+] Created directory: %s\n", path);
    }
}

void generate_suricata_config(const IDSConfig* config) {
    char config_path[256];
    snprintf(config_path, sizeof(config_path), "%s/suricata.yaml", CONFIG_DIR);
    
    FILE* fp = fopen(config_path, "w");
    if(!fp) {
        printf("Error: Cannot create config file %s\n", config_path);
        return;
    }
    
    fprintf(fp, "%%YAML 1.1\n");
    fprintf(fp, "---\n");
    fprintf(fp, "# Suricata configuration\n");
    fprintf(fp, "# Generated: %s\n", __DATE__);
    fprintf(fp, "\n");
    
    fprintf(fp, "vars:\n");
    fprintf(fp, "  address-groups:\n");
    fprintf(fp, "    HOME_NET: \"%s\"\n", config->home_net);
    fprintf(fp, "    EXTERNAL_NET: \"any\"\n");
    fprintf(fp, "    HTTP_SERVERS: \"$HOME_NET\"\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "af-packet:\n");
    fprintf(fp, "  - interface: %s\n", config->interface);
    fprintf(fp, "    cluster-id: 99\n");
    fprintf(fp, "    cluster-type: cluster_flow\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "default-log-dir: %s\n", config->log_dir);
    fprintf(fp, "\n");
    
    fprintf(fp, "outputs:\n");
    fprintf(fp, "  - eve-log:\n");
    fprintf(fp, "      enabled: yes\n");
    fprintf(fp, "      filetype: regular\n");
    fprintf(fp, "      filename: eve.json\n");
    fprintf(fp, "  - fast:\n");
    fprintf(fp, "      enabled: yes\n");
    fprintf(fp, "      filename: fast.log\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "rule-files:\n");
    fprintf(fp, "  - suricata.rules\n");
    fprintf(fp, "  - emerging-threats.rules\n");
    
    fclose(fp);
    printf("[+] Suricata configuration generated: %s\n", config_path);
}

void generate_snort_config(const IDSConfig* config) {
    char config_path[256];
    snprintf(config_path, sizeof(config_path), "%s/snort.conf", CONFIG_DIR);
    
    FILE* fp = fopen(config_path, "w");
    if(!fp) {
        printf("Error: Cannot create config file %s\n", config_path);
        return;
    }
    
    fprintf(fp, "# Snort configuration\n");
    fprintf(fp, "# Generated: %s\n", __DATE__);
    fprintf(fp, "\n");
    
    fprintf(fp, "ipvar HOME_NET %s\n", config->home_net);
    fprintf(fp, "ipvar EXTERNAL_NET any\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "preprocessor stream5_global: max_tcp 8192, track_tcp yes\n");
    fprintf(fp, "preprocessor stream5_tcp: policy first\n");
    fprintf(fp, "preprocessor http_inspect: global iis_unicode_map unicode.map 1252\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "output alert_fast: stdout\n");
    fprintf(fp, "output alert_syslog: LOG_AUTH LOG_ALERT\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "include $RULE_PATH/snort.rules\n");
    fprintf(fp, "include $RULE_PATH/emerging-threats.rules\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "config logdir: %s\n", config->log_dir);
    fprintf(fp, "config interface: %s\n", config->interface);
    
    fclose(fp);
    printf("[+] Snort configuration generated: %s\n", config_path);
}

void generate_sample_rules() {
    char rules_path[256];
    snprintf(rules_path, sizeof(rules_path), "%s/rules/suricata.rules", CONFIG_DIR);
    
    FILE* fp = fopen(rules_path, "w");
    if(!fp) {
        printf("Error: Cannot create rules file %s\n", rules_path);
        return;
    }
    
    fprintf(fp, "# Sample IDS rules\n");
    fprintf(fp, "# Generated: %s\n", __DATE__);
    fprintf(fp, "\n");
    
    // Sample rules
    fprintf(fp, "alert tcp any any -> $HOME_NET 22 (msg:\"SSH connection attempt\"; flow:established; sid:1000001; rev:1;)\n");
    fprintf(fp, "alert tcp any any -> $HOME_NET 80 (msg:\"HTTP web traffic\"; flow:established; sid:1000002; rev:1;)\n");
    fprintf(fp, "alert tcp any any -> $HOME_NET 443 (msg:\"HTTPS web traffic\"; flow:established; sid:1000003; rev:1;)\n");
    fprintf(fp, "alert icmp any any -> $HOME_NET any (msg:\"ICMP traffic detected\"; sid:1000004; rev:1;)\n");
    fprintf(fp, "alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:\"FTP connection attempt\"; sid:1000005; rev:1;)\n");
    
    fclose(fp);
    printf("[+] Sample rules generated: %s\n", rules_path);
}

int parse_rules_file(const char* filename, IDSRule* rules, int max_rules) {
    FILE* fp = fopen(filename, "r");
    if(!fp) {
        printf("Error: Cannot open rules file %s\n", filename);
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    int rule_count = 0;
    
    while(fgets(line, sizeof(line), fp) && rule_count < max_rules) {
        // Skip comments and empty lines
        if(line[0] == '#' || line[0] == '\n') {
            continue;
        }
        
        // Simple rule parsing (in real implementation, use proper parsing)
        if(strstr(line, "alert")) {
            IDSRule* rule = &rules[rule_count];
            
            // Extract SID if present
            char* sid_pos = strstr(line, "sid:");
            if(sid_pos) {
                sscanf(sid_pos, "sid:%19[^;];", rule->sid);
            } else {
                snprintf(rule->sid, sizeof(rule->sid), "UNK%d", rule_count);
            }
            
            // Extract message if present
            char* msg_pos = strstr(line, "msg:");
            if(msg_pos) {
                sscanf(msg_pos, "msg:\"%255[^\"]", rule->message);
            } else {
                strcpy(rule->message, "Unknown alert");
            }
            
            rule->enabled = 1;
            rule_count++;
        }
    }
    
    fclose(fp);
    return rule_count;
}

void display_rules(const IDSRule* rules, int count) {
    printf("\n=== IDS Rules Summary ===\n");
    printf("Total rules: %d\n\n", count);
    
    for(int i = 0; i < count && i < 10; i++) { // Show first 10 rules
        printf("SID: %s\n", rules[i].sid);
        printf("Message: %s\n", rules[i].message);
        printf("Status: %s\n", rules[i].enabled ? "Enabled" : "Disabled");
        printf("---\n");
    }
    
    if(count > 10) {
        printf("... and %d more rules\n", count - 10);
    }
}

void setup_ids_environment() {
    printf("[*] Setting up IDS environment...\n");
    
    // Create directories
    create_directory(CONFIG_DIR);
    create_directory("/var/log/ids");
    create_directory("/etc/ids/rules");
    create_directory("/etc/ids/scripts");
    
    // Initialize configuration
    IDSConfig config = {
        .home_net = "192.168.1.0/24",
        .external_net = "any",
        .interface = "eth0",
        .log_dir = "/var/log/ids",
        .max_rules = 10000
    };
    
    // Generate configurations
    generate_suricata_config(&config);
    generate_snort_config(&config);
    generate_sample_rules();
    
    printf("[+] IDS environment setup completed\n");
}

void print_usage() {
    printf("IDS Setup and Management Tool\n");
    printf("Usage:\n");
    printf("  setup           - Setup IDS environment\n");
    printf("  suricata-config - Generate Suricata configuration\n");
    printf("  snort-config    - Generate Snort configuration\n");
    printf("  list-rules      - List rules from file\n");
    printf("  help            - Show this help\n");
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        print_usage();
        return 1;
    }
    
    if(strcmp(argv[1], "setup") == 0) {
        setup_ids_environment();
    }
    else if(strcmp(argv[1], "suricata-config") == 0) {
        IDSConfig config = {
            .home_net = "192.168.1.0/24",
            .external_net = "any", 
            .interface = "eth0",
            .log_dir = "/var/log/ids",
            .max_rules = 10000
        };
        generate_suricata_config(&config);
    }
    else if(strcmp(argv[1], "snort-config") == 0) {
        IDSConfig config = {
            .home_net = "192.168.1.0/24",
            .external_net = "any",
            .interface = "eth0", 
            .log_dir = "/var/log/ids",
            .max_rules = 10000
        };
        generate_snort_config(&config);
    }
    else if(strcmp(argv[1], "list-rules") == 0) {
        if(argc < 3) {
            printf("Usage: %s list-rules <rules_file>\n", argv[0]);
            return 1;
        }
        
        IDSRule rules[100];
        int count = parse_rules_file(argv[2], rules, 100);
        display_rules(rules, count);
    }
    else if(strcmp(argv[1], "help") == 0) {
        print_usage();
    }
    else {
        printf("Unknown command: %s\n", argv[1]);
        print_usage();
        return 1;
    }
    
    return 0;
}
