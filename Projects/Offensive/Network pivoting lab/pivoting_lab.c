#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MAX_HOSTS 50
#define MAX_SERVICES 20

typedef struct {
    char ip[16];
    char hostname[50];
    char os[50];
    int services[MAX_SERVICES];
    int service_count;
    int compromised;
} NetworkHost;

typedef struct {
    char name[50];
    char subnet[20];
    NetworkHost hosts[10];
    int host_count;
} NetworkSegment;

typedef struct {
    NetworkSegment segments[5];
    int segment_count;
    NetworkHost *current_position;
} PivotingLab;

void initialize_lab(PivotingLab *lab) {
    printf("Initializing Network Pivoting Lab...\n");
    
    // DMZ Segment
    NetworkSegment dmz;
    strcpy(dmz.name, "DMZ");
    strcpy(dmz.subnet, "10.0.1.0/24");
    
    NetworkHost web_server;
    strcpy(web_server.ip, "10.0.1.10");
    strcpy(web_server.hostname, "web-server");
    strcpy(web_server.os, "Linux Ubuntu 20.04");
    web_server.services[0] = 80;  // HTTP
    web_server.services[1] = 22;  // SSH
    web_server.service_count = 2;
    web_server.compromised = 0;
    
    dmz.hosts[0] = web_server;
    dmz.host_count = 1;
    
    // Internal Segment
    NetworkSegment internal;
    strcpy(internal.name, "Internal Network");
    strcpy(internal.subnet, "10.0.2.0/24");
    
    NetworkHost db_server;
    strcpy(db_server.ip, "10.0.2.10");
    strcpy(db_server.hostname, "db-server");
    strcpy(db_server.os, "Linux CentOS 8");
    db_server.services[0] = 3306; // MySQL
    db_server.services[1] = 22;   // SSH
    db_server.service_count = 2;
    db_server.compromised = 0;
    
    internal.hosts[0] = db_server;
    internal.host_count = 1;
    
    lab->segments[0] = dmz;
    lab->segments[1] = internal;
    lab->segment_count = 2;
    lab->current_position = &web_server;
    
    printf("Lab initialized with 2 network segments\n");
}

void network_scan(PivotingLab *lab, const char *subnet) {
    printf("Scanning network: %s\n", subnet);
    
    for (int i = 0; i < lab->segment_count; i++) {
        if (strcmp(lab->segments[i].subnet, subnet) == 0) {
            printf("Found %d hosts in %s:\n", lab->segments[i].host_count, lab->segments[i].name);
            for (int j = 0; j < lab->segments[i].host_count; j++) {
                NetworkHost host = lab->segments[i].hosts[j];
                printf("  %s (%s) - %s\n", host.ip, host.hostname, host.os);
            }
            return;
        }
    }
    
    printf("No hosts found in network %s\n", subnet);
}

void exploit_service(PivotingLab *lab, const char *target_ip, int port) {
    printf("Attempting to exploit service on %s:%d\n", target_ip, port);
    
    for (int i = 0; i < lab->segment_count; i++) {
        for (int j = 0; j < lab->segments[i].host_count; j++) {
            NetworkHost *host = &lab->segments[i].hosts[j];
            if (strcmp(host->ip, target_ip) == 0) {
                // Check if service is available
                int service_found = 0;
                for (int k = 0; k < host->service_count; k++) {
                    if (host->services[k] == port) {
                        service_found = 1;
                        break;
                    }
                }
                
                if (service_found) {
                    if (!host->compromised) {
                        host->compromised = 1;
                        lab->current_position = host;
                        printf("Successfully compromised %s (%s)\n", host->hostname, host->ip);
                        printf("Current position: %s\n", host->hostname);
                    } else {
                        printf("Host %s is already compromised\n", host->hostname);
                    }
                    return;
                }
            }
        }
    }
    
    printf("Failed to exploit service on %s:%d\n", target_ip, port);
}

void create_ssh_tunnel(const char *jump_host, const char *target_host, int target_port, int local_port) {
    printf("Creating SSH tunnel:\n");
    printf("  Jump host: %s\n", jump_host);
    printf("  Target: %s:%d\n", target_host, target_port);
    printf("  Local port: %d\n", local_port);
    printf("SSH tunnel established successfully\n");
}

void setup_socks_proxy(const char *pivot_host, int local_port) {
    printf("Setting up SOCKS proxy:\n");
    printf("  Pivot host: %s\n", pivot_host);
    printf("  Local port: %d\n", local_port);
    printf("SOCKS proxy ready on localhost:%d\n", local_port);
}

void demonstrate_pivoting_scenario() {
    printf("\n=== NETWORK PIVOTING SCENARIO ===\n");
    
    PivotingLab lab;
    initialize_lab(&lab);
    
    printf("\n[PHASE 1] Initial Reconnaissance\n");
    network_scan(&lab, "10.0.1.0/24");
    
    printf("\n[PHASE 2] Initial Compromise\n");
    exploit_service(&lab, "10.0.1.10", 80);
    
    printf("\n[PHASE 3] Internal Network Discovery\n");
    network_scan(&lab, "10.0.2.0/24");
    
    printf("\n[PHASE 4] Pivot Establishment\n");
    create_ssh_tunnel("10.0.1.10", "10.0.2.10", 3306, 3306);
    setup_socks_proxy("10.0.1.10", 1080);
    
    printf("\n[PHASE 5] Lateral Movement\n");
    exploit_service(&lab, "10.0.2.10", 22);
    
    printf("\n[SCENARIO COMPLETE] Successfully pivoted to internal network!\n");
}

void show_pivoting_techniques() {
    printf("\n=== PIVOTING TECHNIQUES ===\n");
    
    printf("\n1. SSH Tunneling:\n");
    printf("   Local Forwarding: ssh -L local_port:remote_host:remote_port user@jump_host\n");
    printf("   Remote Forwarding: ssh -R local_port:remote_host:remote_port user@jump_host\n");
    printf("   Dynamic Forwarding: ssh -D local_port user@jump_host\n");
    
    printf("\n2. SOCKS Proxies:\n");
    printf("   SSH Dynamic: ssh -D 1080 user@pivot_host\n");
    printf("   Proxychains: proxychains nmap -sT target_ip\n");
    
    printf("\n3. Port Forwarding:\n");
    printf("   netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=target_ip\n");
    
    printf("\n4. VPN Pivoting:\n");
    printf("   OpenVPN through compromised host\n");
    printf("   SSH VPN: ssh -w 0:0 user@pivot_host\n");
    
    printf("\n5. DNS Tunneling:\n");
    printf("   dnscat2, iodine\n");
    printf("   Data exfiltration through DNS queries\n");
}

void show_lateral_movement_techniques() {
    printf("\n=== LATERAL MOVEMENT TECHNIQUES ===\n");
    
    printf("\n1. Windows Environments:\n");
    printf("   PsExec: psexec \\\\target_ip -u user -p pass cmd.exe\n");
    printf("   WMI: wmic /node:target_ip process call create 'cmd.exe'\n");
    printf("   PowerShell Remoting: Enter-PSSession -ComputerName target_ip\n");
    
    printf("\n2. Linux Environments:\n");
    printf("   SSH: ssh user@target_ip\n");
    printf("   RSH/rlogin: rsh target_ip -l user\n");
    
    printf("\n3. Credential Reuse:\n");
    printf("   Pass-the-Hash: pth-winexe -U user%hash //target_ip cmd\n");
    printf("   Pass-the-Ticket: export KRB5CCNAME=/path/to/ticket && kinit\n");
    
    printf("\n4. Service Exploitation:\n");
    printf("   SMB: smbclient //target_ip/share -U user\n");
    printf("   RDP: xfreerdp /v:target_ip /u:user /p:pass\n");
}

int main() {
    printf("Network Pivoting Lab Scripts\n");
    printf("============================\n");
    printf("FOR AUTHORIZED PENETRATION TESTING ONLY\n\n");
    
    demonstrate_pivoting_scenario();
    show_pivoting_techniques();
    show_lateral_movement_techniques();
    
    printf("\n=== SECURITY BEST PRACTICES ===\n");
    printf("✅ Use dedicated jump boxes for network segmentation\n");
    printf("✅ Implement multi-factor authentication\n");
    printf("✅ Monitor for unusual lateral movement\n");
    printf("✅ Use application whitelisting\n");
    printf("✅ Regularly patch and update systems\n");
    printf("✅ Implement network segmentation\n");
    printf("✅ Use privileged access management\n");
    
    return 0;
}
