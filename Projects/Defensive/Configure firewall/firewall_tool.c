/**
 * Firewall Rule Automation - C Implementation
 * Basic rule validation and iptables generation
 * Compile: gcc -o firewall_tool firewall_tool.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_RULES 100
#define MAX_RULE_LENGTH 256
#define MAX_FIELD_LENGTH 50

typedef struct {
    char name[MAX_FIELD_LENGTH];
    char action[MAX_FIELD_LENGTH];     // allow, deny, drop
    char protocol[MAX_FIELD_LENGTH];   // tcp, udp, icmp, any
    char src[MAX_FIELD_LENGTH];        // IP/CIDR
    char dst[MAX_FIELD_LENGTH];        // IP/CIDR
    char sport[MAX_FIELD_LENGTH];      // source port
    char dport[MAX_FIELD_LENGTH];      // destination port
    char description[MAX_FIELD_LENGTH];
    int enabled;
} FirewallRule;

typedef struct {
    FirewallRule rules[MAX_RULES];
    int count;
} FirewallRuleSet;

int validate_ip_cidr(const char* ip_cidr) {
    if(strcmp(ip_cidr, "any") == 0) {
        return 1;
    }
    
    // Check if it's a simple IP address
    struct in_addr addr;
    if(inet_pton(AF_INET, ip_cidr, &addr) == 1) {
        return 1;
    }
    
    // Check if it's CIDR notation
    char ip[50];
    char* slash = strchr(ip_cidr, '/');
    if(slash) {
        strncpy(ip, ip_cidr, slash - ip_cidr);
        ip[slash - ip_cidr] = '\0';
        
        if(inet_pton(AF_INET, ip, &addr) == 1) {
            int mask = atoi(slash + 1);
            if(mask >= 0 && mask <= 32) {
                return 1;
            }
        }
    }
    
    return 0;
}

int validate_port(const char* port) {
    if(strcmp(port, "any") == 0 || strcmp(port, "") == 0) {
        return 1;
    }
    
    // Single port
    if(isdigit(port[0])) {
        int p = atoi(port);
        if(p >= 1 && p <= 65535) {
            return 1;
        }
    }
    
    // Port range (start:end)
    char* colon = strchr(port, ':');
    if(colon) {
        char start[10], end[10];
        strncpy(start, port, colon - port);
        start[colon - port] = '\0';
        strcpy(end, colon + 1);
        
        if(isdigit(start[0]) && isdigit(end[0])) {
            int s = atoi(start), e = atoi(end);
            if(s >= 1 && s <= 65535 && e >= 1 && e <= 65535 && s <= e) {
                return 1;
            }
        }
    }
    
    return 0;
}

int validate_rule(const FirewallRule* rule) {
    // Validate action
    if(strcmp(rule->action, "allow") != 0 && 
       strcmp(rule->action, "deny") != 0 && 
       strcmp(rule->action, "drop") != 0) {
        printf("Error: Invalid action '%s'\n", rule->action);
        return 0;
    }
    
    // Validate protocol
    if(strcmp(rule->protocol, "tcp") != 0 && 
       strcmp(rule->protocol, "udp") != 0 && 
       strcmp(rule->protocol, "icmp") != 0 && 
       strcmp(rule->protocol, "any") != 0) {
        printf("Error: Invalid protocol '%s'\n", rule->protocol);
        return 0;
    }
    
    // Validate IP addresses
    if(!validate_ip_cidr(rule->src)) {
        printf("Error: Invalid source IP/CIDR '%s'\n", rule->src);
        return 0;
    }
    
    if(!validate_ip_cidr(rule->dst)) {
        printf("Error: Invalid destination IP/CIDR '%s'\n", rule->dst);
        return 0;
    }
    
    // Validate ports
    if(!validate_port(rule->sport)) {
        printf("Error: Invalid source port '%s'\n", rule->sport);
        return 0;
    }
    
    if(!validate_port(rule->dport)) {
        printf("Error: Invalid destination port '%s'\n", rule->dport);
        return 0;
    }
    
    // Protocol-port consistency
    if((strcmp(rule->protocol, "tcp") == 0 || strcmp(rule->protocol, "udp") == 0) && 
       strcmp(rule->dport, "any") == 0) {
        printf("Warning: TCP/UDP rule without specific destination port\n");
    }
    
    return 1;
}

void init_rule_set(FirewallRuleSet* rule_set) {
    rule_set->count = 0;
}

int add_rule(FirewallRuleSet* rule_set, const FirewallRule* rule) {
    if(rule_set->count >= MAX_RULES) {
        printf("Error: Rule set is full\n");
        return 0;
    }
    
    if(!validate_rule(rule)) {
        return 0;
    }
    
    // Check for duplicates
    for(int i = 0; i < rule_set->count; i++) {
        FirewallRule* existing = &rule_set->rules[i];
        if(strcmp(existing->protocol, rule->protocol) == 0 &&
           strcmp(existing->src, rule->src) == 0 &&
           strcmp(existing->dst, rule->dst) == 0 &&
           strcmp(existing->sport, rule->sport) == 0 &&
           strcmp(existing->dport, rule->dport) == 0) {
            printf("Error: Duplicate rule detected\n");
            return 0;
        }
    }
    
    rule_set->rules[rule_set->count] = *rule;
    rule_set->count++;
    return 1;
}

void generate_iptables_config(const FirewallRuleSet* rule_set, const char* output_file) {
    FILE* fp = output_file ? fopen(output_file, "w") : stdout;
    
    if(!fp) {
        printf("Error: Cannot open output file\n");
        return;
    }
    
    fprintf(fp, "# iptables configuration\n");
    fprintf(fp, "# Generated automatically\n\n");
    
    fprintf(fp, "# Flush existing rules\n");
    fprintf(fp, "iptables -F\n");
    fprintf(fp, "iptables -X\n\n");
    
    fprintf(fp, "# Default policies\n");
    fprintf(fp, "iptables -P INPUT DROP\n");
    fprintf(fp, "iptables -P FORWARD DROP\n");
    fprintf(fp, "iptables -P OUTPUT ACCEPT\n\n");
    
    fprintf(fp, "# Allow loopback\n");
    fprintf(fp, "iptables -A INPUT -i lo -j ACCEPT\n");
    fprintf(fp, "iptables -A OUTPUT -o lo -j ACCEPT\n\n");
    
    fprintf(fp, "# Allow established connections\n");
    fprintf(fp, "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n\n");
    
    fprintf(fp, "# Custom rules\n");
    
    for(int i = 0; i < rule_set->count; i++) {
        FirewallRule* rule = &rule_set->rules[i];
        
        if(!rule->enabled) {
            continue;
        }
        
        if(strlen(rule->description) > 0) {
            fprintf(fp, "# %s\n", rule->description);
        }
        
        char target[20];
        if(strcmp(rule->action, "allow") == 0) {
            strcpy(target, "ACCEPT");
        } else {
            strcpy(target, "DROP");
        }
        
        char protocol[10];
        if(strcmp(rule->protocol, "any") == 0) {
            strcpy(protocol, "all");
        } else {
            strcpy(protocol, rule->protocol);
        }
        
        char sport[50] = "";
        if(strcmp(rule->sport, "any") != 0 && strlen(rule->sport) > 0) {
            snprintf(sport, sizeof(sport), "--sport %s", rule->sport);
        }
        
        char dport[50] = "";
        if(strcmp(rule->dport, "any") != 0 && strlen(rule->dport) > 0) {
            snprintf(dport, sizeof(dport), "--dport %s", rule->dport);
        }
        
        fprintf(fp, "iptables -A INPUT -p %s -s %s -d %s %s %s -j %s\n",
                protocol, rule->src, rule->dst, sport, dport, target);
    }
    
    fprintf(fp, "\n# Save rules\n");
    fprintf(fp, "iptables-save > /etc/iptables/rules.v4\n");
    
    if(output_file) {
        fclose(fp);
        printf("iptables configuration saved to: %s\n", output_file);
    }
}

void print_rules(const FirewallRuleSet* rule_set) {
    printf("\nFirewall Rules (%d total):\n", rule_set->count);
    printf("=========================================\n");
    
    for(int i = 0; i < rule_set->count; i++) {
        FirewallRule* rule = &rule_set->rules[i];
        printf("Rule %d: %s\n", i + 1, rule->name);
        printf("  Action: %s\n", rule->action);
        printf("  Protocol: %s\n", rule->protocol);
        printf("  Source: %s\n", rule->src);
        printf("  Destination: %s\n", rule->dst);
        printf("  Source Port: %s\n", rule->sport);
        printf("  Dest Port: %s\n", rule->dport);
        printf("  Description: %s\n", rule->description);
        printf("  Enabled: %s\n", rule->enabled ? "Yes" : "No");
        printf("-----------------------------------------\n");
    }
}

void print_usage() {
    printf("Firewall Rule Automation Tool\n");
    printf("Usage:\n");
    printf("  add <name> <action> <protocol> <src> <dst> [sport] [dport] [desc]\n");
    printf("  list\n");
    printf("  generate-iptables [output_file]\n");
    printf("  validate\n");
    printf("  help\n");
}

int main(int argc, char* argv[]) {
    if(argc < 2) {
        print_usage();
        return 1;
    }
    
    FirewallRuleSet rule_set;
    init_rule_set(&rule_set);
    
    // Add some sample rules
    FirewallRule sample_rules[] = {
        {"ssh", "allow", "tcp", "any", "any", "any", "22", "SSH access", 1},
        {"web", "allow", "tcp", "any", "any", "any", "80,443", "Web traffic", 1},
        {"dns", "allow", "udp", "any", "any", "any", "53", "DNS", 1},
        {"icmp", "allow", "icmp", "any", "any", "any", "any", "Ping", 1},
        {"block-rdp", "deny", "tcp", "any", "any", "any", "3389", "Block RDP", 1}
    };
    
    for(int i = 0; i < 5; i++) {
        add_rule(&rule_set, &sample_rules[i]);
    }
    
    if(strcmp(argv[1], "add") == 0 && argc >= 6) {
        FirewallRule new_rule;
        
        strncpy(new_rule.name, argv[2], MAX_FIELD_LENGTH);
        strncpy(new_rule.action, argv[3], MAX_FIELD_LENGTH);
        strncpy(new_rule.protocol, argv[4], MAX_FIELD_LENGTH);
        strncpy(new_rule.src, argv[5], MAX_FIELD_LENGTH);
        strncpy(new_rule.dst, argv[6], MAX_FIELD_LENGTH);
        
        // Optional parameters
        if(argc > 7) strncpy(new_rule.sport, argv[7], MAX_FIELD_LENGTH);
        else strcpy(new_rule.sport, "any");
        
        if(argc > 8) strncpy(new_rule.dport, argv[8], MAX_FIELD_LENGTH);
        else strcpy(new_rule.dport, "any");
        
        if(argc > 9) strncpy(new_rule.description, argv[9], MAX_FIELD_LENGTH);
        else strcpy(new_rule.description, "");
        
        new_rule.enabled = 1;
        
        if(add_rule(&rule_set, &new_rule)) {
            printf("Rule added successfully: %s\n", new_rule.name);
        } else {
            printf("Failed to add rule: %s\n", new_rule.name);
        }
    }
    else if(strcmp(argv[1], "list") == 0) {
        print_rules(&rule_set);
    }
    else if(strcmp(argv[1], "generate-iptables") == 0) {
        const char* output_file = argc > 2 ? argv[2] : NULL;
        generate_iptables_config(&rule_set, output_file);
    }
    else if(strcmp(argv[1], "validate") == 0) {
        printf("Validating all rules...\n");
        int valid_count = 0;
        for(int i = 0; i < rule_set.count; i++) {
            if(validate_rule(&rule_set.rules[i])) {
                valid_count++;
            }
        }
        printf("Validation complete: %d/%d rules valid\n", valid_count, rule_set.count);
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
