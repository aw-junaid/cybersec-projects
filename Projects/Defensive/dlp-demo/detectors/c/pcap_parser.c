/**
 * DLP PCAP Parser - Lab Use Only
 * Offline analysis of PCAP files for data exfiltration patterns
 * WARNING: This tool is for lab demonstration only. Never use on production networks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <jansson.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define MAX_PAYLOAD 4096
#define DNS_PORT 53
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define FTP_PORT 21
#define SMTP_PORT 25

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t protocol;
    size_t payload_len;
    char heuristic_triggers[512];
} stream_metadata_t;

typedef struct {
    stream_metadata_t *streams;
    size_t count;
    size_t capacity;
} analysis_results_t;

void init_results(analysis_results_t *results) {
    results->capacity = 100;
    results->count = 0;
    results->streams = malloc(results->capacity * sizeof(stream_metadata_t));
}

void free_results(analysis_results_t *results) {
    free(results->streams);
}

void add_stream(analysis_results_t *results, const stream_metadata_t *stream) {
    if (results->count >= results->capacity) {
        results->capacity *= 2;
        results->streams = realloc(results->streams, results->capacity * sizeof(stream_metadata_t));
    }
    results->streams[results->count++] = *stream;
}

int is_suspicious_port(uint16_t port) {
    return (port == FTP_PORT || port == SMTP_PORT || port == 4444 || port == 8080 || port == 8443);
}

void analyze_dns_packet(const u_char *payload, size_t len, stream_metadata_t *stream) {
    // Simple DNS analysis - look for long queries (potential tunneling)
    if (len > 100) {
        strcat(stream->heuristic_triggers, "long_dns_query,");
    }
    
    // Check for TXT queries
    if (len > 12 && (payload[2] & 0x80) == 0) {  // DNS query
        int qdcount = (payload[4] << 8) | payload[5];
        if (qdcount > 0) {
            // Simple check: look for TXT type (16)
            const u_char *pos = payload + 12;
            while (pos < payload + len && *pos != 0) pos++;  // Skip QNAME
            if (pos + 4 < payload + len) {
                uint16_t qtype = (pos[1] << 8) | pos[2];
                if (qtype == 16) {  // TXT record
                    strcat(stream->heuristic_triggers, "dns_txt_query,");
                }
            }
        }
    }
}

void analyze_http_packet(const u_char *payload, size_t len, stream_metadata_t *stream) {
    const char *http_methods[] = {"POST", "PUT", "GET", "HEAD"};
    
    for (int i = 0; i < 4; i++) {
        if (strncmp((const char*)payload, http_methods[i], strlen(http_methods[i])) == 0) {
            if (i == 0 || i == 1) {  // POST or PUT
                strcat(stream->heuristic_triggers, "http_upload,");
                
                // Check for large content (simplified)
                if (len > 1000) {
                    strcat(stream->heuristic_triggers, "large_http_body,");
                }
            }
            break;
        }
    }
}

void analyze_ftp_packet(const u_char *payload, size_t len, stream_metadata_t *stream) {
    if (strncmp((const char*)payload, "STOR", 4) == 0 ||
        strncmp((const char*)payload, "STOU", 4) == 0) {
        strcat(stream->heuristic_triggers, "ftp_upload,");
    }
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    analysis_results_t *results = (analysis_results_t *)user_data;
    
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    if (ntohs(eth_header->h_proto) != ETH_P_IP) return;
    
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    if (ip_header->protocol != IPPROTO_TCP && ip_header->protocol != IPPROTO_UDP) return;
    
    stream_metadata_t stream = {0};
    
    // Extract IP addresses
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->saddr;
    dst_addr.s_addr = ip_header->daddr;
    
    inet_ntop(AF_INET, &src_addr, stream.src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, stream.dst_ip, INET_ADDRSTRLEN);
    
    stream.protocol = ip_header->protocol;
    
    // Extract ports and payload
    size_t ip_header_len = ip_header->ihl * 4;
    const u_char *transport_layer = packet + sizeof(struct ethhdr) + ip_header_len;
    
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)transport_layer;
        stream.src_port = ntohs(tcp_header->source);
        stream.dst_port = ntohs(tcp_header->dest);
        
        size_t tcp_header_len = tcp_header->doff * 4;
        const u_char *payload = transport_layer + tcp_header_len;
        stream.payload_len = pkthdr->len - (sizeof(struct ethhdr) + ip_header_len + tcp_header_len);
        
        // Protocol-specific analysis
        if (stream.dst_port == DNS_PORT) {
            analyze_dns_packet(payload, stream.payload_len, &stream);
        } else if (stream.dst_port == HTTP_PORT) {
            analyze_http_packet(payload, stream.payload_len, &stream);
        } else if (stream.dst_port == FTP_PORT) {
            analyze_ftp_packet(payload, stream.payload_len, &stream);
        }
        
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)transport_layer;
        stream.src_port = ntohs(udp_header->source);
        stream.dst_port = ntohs(udp_header->dest);
        
        const u_char *payload = transport_layer + sizeof(struct udphdr);
        stream.payload_len = ntohs(udp_header->len) - sizeof(struct udphdr);
        
        if (stream.dst_port == DNS_PORT) {
            analyze_dns_packet(payload, stream.payload_len, &stream);
        }
    }
    
    // Check for suspicious ports
    if (is_suspicious_port(stream.dst_port)) {
        strcat(stream.heuristic_triggers, "suspicious_port,");
    }
    
    // Only add if we found something suspicious
    if (strlen(stream.heuristic_triggers) > 0) {
        add_stream(results, &stream);
    }
}

json_t *results_to_json(const analysis_results_t *results) {
    json_t *root = json_object();
    json_t *streams_array = json_array();
    
    for (size_t i = 0; i < results->count; i++) {
        const stream_metadata_t *stream = &results->streams[i];
        
        json_t *stream_obj = json_object();
        json_object_set_new(stream_obj, "source_ip", json_string(stream->src_ip));
        json_object_set_new(stream_obj, "destination_ip", json_string(stream->dst_ip));
        json_object_set_new(stream_obj, "source_port", json_integer(stream->src_port));
        json_object_set_new(stream_obj, "destination_port", json_integer(stream->dst_port));
        json_object_set_new(stream_obj, "protocol", 
                           json_string(stream->protocol == IPPROTO_TCP ? "TCP" : "UDP"));
        json_object_set_new(stream_obj, "payload_size", json_integer(stream->payload_len));
        json_object_set_new(stream_obj, "heuristics", json_string(stream->heuristic_triggers));
        
        json_array_append_new(streams_array, stream_obj);
    }
    
    json_object_set_new(root, "suspicious_streams", streams_array);
    json_object_set_new(root, "total_analyzed", json_integer(results->count));
    
    return root;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        fprintf(stderr, "WARNING: This tool is for lab use only. Never run on production data.\n");
        return 1;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }
    
    analysis_results_t results;
    init_results(&results);
    
    // Process packets
    if (pcap_loop(handle, 0, packet_handler, (u_char *)&results) < 0) {
        fprintf(stderr, "Error processing pcap file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        free_results(&results);
        return 1;
    }
    
    pcap_close(handle);
    
    // Convert to JSON and output
    json_t *json_output = results_to_json(&results);
    char *json_str = json_dumps(json_output, JSON_INDENT(2));
    printf("%s\n", json_str);
    
    // Cleanup
    free(json_str);
    json_decref(json_output);
    free_results(&results);
    
    return 0;
}
