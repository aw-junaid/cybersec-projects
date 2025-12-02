/**
 * PCAP Parser for Threat Intelligence Pipeline
 * 
 * Extracts IOCs from PCAP files:
 * - IP addresses from flows
 * - Domains from DNS queries and SSL SNI
 * - SSL certificate fingerprints
 * 
 * Compile: gcc -o pcap_parser pcap_parser.c -lpcap -ljansson -lssl -lcrypto
 * Usage: ./pcap_parser input.pcap > iocs.json
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <jansson.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define MAX_SNI_LEN 256
#define MAX_DOMAIN_LEN 253
#define MAX_CERT_HASH 65

typedef struct {
    json_t *iocs;
    int packet_count;
} parser_state_t;

// Function prototypes
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void extract_dns_queries(const u_char *payload, int len, json_t *iocs);
void extract_ssl_sni(const u_char *payload, int len, json_t *iocs);
char* extract_cert_fingerprint(const u_char *payload, int len);
void add_ioc(json_t *iocs, const char *type, const char *value, const char *source);

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    parser_state_t *state = (parser_state_t *)args;
    struct ip *ip_header;
    struct ip6_hdr *ip6_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    u_int ip_len;
    u_int size_ip;
    u_int size_tcp;
    u_int size_udp;
    u_int sport, dport;

    state->packet_count++;

    // Skip Ethernet header
    const u_char *ip_packet = packet + sizeof(struct ether_header);
    u_int remaining_len = header->caplen - sizeof(struct ether_header);

    if (remaining_len < sizeof(struct ip)) {
        return; // Packet too short
    }

    // Check IP version
    ip_header = (struct ip *)ip_packet;
    if (ip_header->ip_v == 4) {
        // IPv4
        size_ip = ip_header->ip_hl * 4;
        if (size_ip < 20 || remaining_len < size_ip) {
            return; // Invalid IP header
        }

        // Extract source/dest IPs
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        add_ioc(state->iocs, "ipv4", src_ip, "pcap");
        add_ioc(state->iocs, "ipv4", dst_ip, "pcap");

        // Check protocol
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: {
                tcp_header = (struct tcphdr *)(ip_packet + size_ip);
                size_tcp = tcp_header->th_off * 4;
                if (size_tcp < 20) break;

                sport = ntohs(tcp_header->th_sport);
                dport = ntohs(tcp_header->th_dport);

                // Check for common ports
                const u_char *tcp_payload = ip_packet + size_ip + size_tcp;
                u_int tcp_payload_len = remaining_len - size_ip - size_tcp;

                if (tcp_payload_len > 0) {
                    // SSL/TLS on port 443, 993, 995, etc.
                    if (dport == 443 || sport == 443 || dport == 993 || sport == 993) {
                        extract_ssl_sni(tcp_payload, tcp_payload_len, state->iocs);
                    }
                }
                break;
            }
            case IPPROTO_UDP: {
                udp_header = (struct udphdr *)(ip_packet + size_ip);
                size_udp = sizeof(struct udphdr);

                sport = ntohs(udp_header->uh_sport);
                dport = ntohs(udp_header->uh_dport);

                // DNS on port 53
                if (dport == 53 || sport == 53) {
                    const u_char *udp_payload = ip_packet + size_ip + size_udp;
                    u_int udp_payload_len = remaining_len - size_ip - size_udp;
                    extract_dns_queries(udp_payload, udp_payload_len, state->iocs);
                }
                break;
            }
        }
    } else if (ip_header->ip_v == 6) {
        // IPv6 (simplified handling)
        ip6_header = (struct ip6_hdr *)ip_packet;
        size_ip = sizeof(struct ip6_hdr);

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        add_ioc(state->iocs, "ipv6", src_ip, "pcap");
        add_ioc(state->iocs, "ipv6", dst_ip, "pcap");
    }
}

void extract_dns_queries(const u_char *payload, int len, json_t *iocs) {
    if (len < 12) return; // DNS header is 12 bytes

    // Skip DNS header and check question section
    const u_char *ptr = payload + 12;
    int remaining = len - 12;

    while (remaining > 0 && *ptr != 0) {
        int label_len = *ptr;
        if (label_len == 0 || label_len >= remaining) break;

        ptr++;
        remaining--;

        char domain[MAX_DOMAIN_LEN] = {0};
        int domain_len = 0;

        while (label_len > 0 && label_len < remaining && domain_len < MAX_DOMAIN_LEN - 1) {
            if (domain_len > 0) {
                domain[domain_len++] = '.';
            }
            memcpy(domain + domain_len, ptr, label_len);
            domain_len += label_len;
            ptr += label_len;
            remaining -= label_len;

            label_len = *ptr;
            ptr++;
            remaining--;
        }

        if (domain_len > 0) {
            add_ioc(iocs, "domain", domain, "dns");
        }

        // Skip QTYPE and QCLASS (4 bytes)
        if (remaining >= 4) {
            ptr += 4;
            remaining -= 4;
        } else {
            break;
        }
    }
}

void extract_ssl_sni(const u_char *payload, int len, json_t *iocs) {
    if (len < 5 || payload[0] != 0x16) return; // SSL Handshake

    // Skip to Client Hello
    const u_char *ptr = payload + 5; // Skip record header
    int remaining = len - 5;

    if (remaining < 4) return;

    // Find extensions
    while (remaining > 4) {
        if (ptr[0] == 0x00 && ptr[1] == 0x00 && ptr[2] == 0x00) {
            // Extension type 0x0000 is server_name
            if (ptr[3] == 0x00) {
                int ext_len = (ptr[4] << 8) | ptr[5];
                if (ext_len > 0 && remaining >= ext_len + 6) {
                    const u_char *sni_data = ptr + 6;
                    int sni_len = (sni_data[0] << 8) | sni_data[1];
                    if (sni_len > 0 && sni_len <= MAX_SNI_LEN && sni_len <= ext_len - 2) {
                        char sni[MAX_SNI_LEN + 1] = {0};
                        memcpy(sni, sni_data + 2, sni_len);
                        sni[sni_len] = '\0';
                        add_ioc(iocs, "domain", sni, "ssl_sni");
                    }
                }
                break;
            }
        }
        ptr++;
        remaining--;
    }
}

void add_ioc(json_t *iocs, const char *type, const char *value, const char *source) {
    // Check if we already have this IOC
    size_t index;
    json_t *entry;
    
    json_array_foreach(iocs, index, entry) {
        const char *existing_type = json_string_value(json_object_get(entry, "type"));
        const char *existing_value = json_string_value(json_object_get(entry, "value"));
        
        if (existing_type && existing_value && 
            strcmp(existing_type, type) == 0 && 
            strcmp(existing_value, value) == 0) {
            return; // Already exists
        }
    }
    
    // Add new IOC
    json_t *ioc = json_object();
    json_object_set_new(ioc, "type", json_string(type));
    json_object_set_new(ioc, "value", json_string(value));
    json_object_set_new(ioc, "source", json_string(source));
    json_object_set_new(ioc, "timestamp", json_string("2024-01-01T00:00:00Z")); // Placeholder
    
    json_array_append_new(iocs, ioc);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open PCAP file
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 2;
    }

    // Initialize parser state
    parser_state_t state;
    state.iocs = json_array();
    state.packet_count = 0;

    // Process packets
    pcap_loop(handle, 0, process_packet, (u_char *)&state);

    // Create output
    json_t *output = json_object();
    json_object_set_new(output, "iocs", state.iocs);
    json_object_set_new(output, "packets_processed", json_integer(state.packet_count));
    json_object_set_new(output, "unique_iocs", json_integer(json_array_size(state.iocs)));

    // Print JSON output
    char *output_str = json_dumps(output, JSON_INDENT(2));
    printf("%s\n", output_str);

    // Cleanup
    free(output_str);
    json_decref(output);
    pcap_close(handle);

    return 0;
}
