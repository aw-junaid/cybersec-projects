/**
 * PCAP Extractor for Honeynet
 * Safety Notice: This tool is for lab use only. Do not use on production networks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <time.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 65536
#define MAX_FILE_SIZE 10485760  // 10MB

typedef struct {
    char source_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t timestamp;
    uint16_t payload_length;
    unsigned char *payload;
    char protocol[16];
} packet_info_t;

typedef struct {
    char hash[SHA256_DIGEST_LENGTH * 2 + 1];
    size_t size;
    double entropy;
    char content_type[64];
} file_info_t;

double calculate_entropy(unsigned char *data, size_t len) {
    if (len == 0) return 0.0;
    
    int freq[256] = {0};
    double entropy = 0.0;
    
    // Calculate byte frequencies
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }
    
    // Calculate entropy
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double probability = (double)freq[i] / len;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

void compute_sha256(unsigned char *data, size_t len, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[SHA256_DIGEST_LENGTH * 2] = 0;
}

json_t *extract_http_file(unsigned char *payload, size_t len) {
    // Simple HTTP file extraction from POST requests
    char *content_start = strstr((char*)payload, "\r\n\r\n");
    if (!content_start) return NULL;
    
    content_start += 4;
    size_t header_len = content_start - (char*)payload;
    
    if (len - header_len > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large, skipping\n");
        return NULL;
    }
    
    file_info_t file_info;
    file_info.size = len - header_len;
    file_info.entropy = calculate_entropy((unsigned char*)content_start, file_info.size);
    
    compute_sha256((unsigned char*)content_start, file_info.size, file_info.hash);
    
    // Simple content type detection
    strncpy(file_info.content_type, "application/octet-stream", sizeof(file_info.content_type));
    
    if (strstr((char*)payload, "Content-Type: ")) {
        char *ct_start = strstr((char*)payload, "Content-Type: ");
        if (ct_start) {
            ct_start += 14;
            char *ct_end = strstr(ct_start, "\r\n");
            if (ct_end && (ct_end - ct_start) < 63) {
                strncpy(file_info.content_type, ct_start, ct_end - ct_start);
                file_info.content_type[ct_end - ct_start] = 0;
            }
        }
    }
    
    // Create JSON object
    json_t *file_obj = json_object();
    json_object_set_new(file_obj, "hash", json_string(file_info.hash));
    json_object_set_new(file_obj, "size", json_integer(file_info.size));
    json_object_set_new(file_obj, "entropy", json_real(file_info.entropy));
    json_object_set_new(file_obj, "content_type", json_string(file_info.content_type));
    
    return file_obj;
}

void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
    json_t *root = (json_t*)user;
    json_t *packets = json_object_get(root, "packets");
    
    packet_info_t pkt_info;
    memset(&pkt_info, 0, sizeof(packet_info_t));
    
    // Extract Ethernet header (simplified)
    struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header
    if (header->len < 14 + sizeof(struct ip)) return;
    
    // Extract IP information
    inet_ntop(AF_INET, &(ip_header->ip_src), pkt_info.source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), pkt_info.dest_ip, INET_ADDRSTRLEN);
    
    pkt_info.timestamp = header->ts.tv_sec;
    
    // Check protocol
    if (ip_header->ip_p == IPPROTO_TCP) {
        strcpy(pkt_info.protocol, "tcp");
        
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        pkt_info.source_port = ntohs(tcp_header->source);
        pkt_info.dest_port = ntohs(tcp_header->dest);
        
        // Calculate payload
        size_t header_size = 14 + (ip_header->ip_hl * 4) + (tcp_header->doff * 4);
        pkt_info.payload_length = header->len - header_size;
        
        if (pkt_info.payload_length > 0 && pkt_info.payload_length < MAX_PACKET_SIZE) {
            pkt_info.payload = malloc(pkt_info.payload_length);
            if (pkt_info.payload) {
                memcpy(pkt_info.payload, packet + header_size, pkt_info.payload_length);
                
                // Check for HTTP traffic
                if (pkt_info.dest_port == 80 || pkt_info.source_port == 80) {
                    json_t *file_obj = extract_http_file(pkt_info.payload, pkt_info.payload_length);
                    if (file_obj) {
                        json_t *files = json_object_get(root, "extracted_files");
                        json_array_append_new(files, file_obj);
                    }
                }
            }
        }
    }
    
    // Create packet JSON
    json_t *packet_obj = json_object();
    json_object_set_new(packet_obj, "timestamp", json_integer(pkt_info.timestamp));
    json_object_set_new(packet_obj, "source_ip", json_string(pkt_info.source_ip));
    json_object_set_new(packet_obj, "dest_ip", json_string(pkt_info.dest_ip));
    json_object_set_new(packet_obj, "source_port", json_integer(pkt_info.source_port));
    json_object_set_new(packet_obj, "dest_port", json_integer(pkt_info.dest_port));
    json_object_set_new(packet_obj, "protocol", json_string(pkt_info.protocol));
    json_object_set_new(packet_obj, "length", json_integer(pkt_info.payload_length));
    
    if (pkt_info.payload_length > 0) {
        char payload_hash[SHA256_DIGEST_LENGTH * 2 + 1];
        compute_sha256(pkt_info.payload, pkt_info.payload_length, payload_hash);
        json_object_set_new(packet_obj, "payload_hash", json_string(payload_hash));
    }
    
    json_array_append_new(packets, packet_obj);
    
    if (pkt_info.payload) {
        free(pkt_info.payload);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        fprintf(stderr, "Safety: This tool is for lab use only\n");
        return 2;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    
    if (!handle) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }
    
    // Create root JSON object
    json_t *root = json_object();
    json_object_set_new(root, "pcap_file", json_string(argv[1]));
    json_object_set_new(root, "analysis_time", json_integer(time(NULL)));
    json_object_set_new(root, "packets", json_array());
    json_object_set_new(root, "extracted_files", json_array());
    
    // Process packets
    if (pcap_loop(handle, 0, packet_handler, (unsigned char*)root) == -1) {
        fprintf(stderr, "Error processing pcap file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        json_decref(root);
        return 1;
    }
    
    pcap_close(handle);
    
    // Output JSON
    char *output = json_dumps(root, JSON_INDENT(2));
    printf("%s\n", output);
    
    free(output);
    json_decref(root);
    
    return 0;
}
