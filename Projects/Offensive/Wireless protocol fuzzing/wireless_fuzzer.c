/**
 * Wireless Protocol Fuzzer - C Implementation
 * Compile: gcc -o wireless_fuzzer wireless_fuzzer.c -lpcap
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define MAX_FRAME_SIZE 2048
#define FUZZ_PATTERNS 8

typedef struct {
    char *protocol;
    unsigned char base_frame[16];
    size_t base_len;
} protocol_config_t;

// Fuzz patterns
unsigned char *fuzz_patterns[FUZZ_PATTERNS] = {
    (unsigned char*)"\x00\x00\x00\x00",  // Null bytes
    (unsigned char*)"\xFF\xFF\xFF\xFF",  // Max bytes
    (unsigned char*)"AAAA",              // All 'A's
    (unsigned char*)"\x00\x01\x02\x03",  // Incremental
    (unsigned char*)"%s%s%s%s",          // Format strings
    (unsigned char*)"../../../etc/passwd", // Path traversal
    (unsigned char*)"<script>",          // XSS
    (unsigned char*)"OR1=1"              // SQL injection
};

// Protocol configurations
protocol_config_t protocols[] = {
    {"zigbee", {0x01, 0x08, 0x00, 0x00}, 4},
    {"lora", {0x40, 0x00, 0x00, 0x00}, 4},
    {"80211", {0x00, 0x00, 0x0C, 0x00}, 4}
};

// 802.11 frame structure
typedef struct {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t sequence[2];
    uint8_t payload[0];
} ieee80211_frame_t;

void generate_random_mac(uint8_t *mac) {
    for(int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
}

void fuzz_zigbee_frame(unsigned char *frame, size_t *len) {
    // Zigbee NWK frame structure
    unsigned char nwk_frame[] = {
        0x01, 0x08,  // Frame control
        0x00, 0x00,  // Destination
        0x00, 0x00,  // Source
        0x1E,        // Radius
        rand() % 256, // Sequence number
    };
    
    memcpy(frame, nwk_frame, sizeof(nwk_frame));
    *len = sizeof(nwk_frame);
    
    // Add fuzz data
    unsigned char *fuzz_data = fuzz_patterns[rand() % FUZZ_PATTERNS];
    size_t fuzz_len = strlen((char*)fuzz_data);
    
    if(*len + fuzz_len < MAX_FRAME_SIZE) {
        memcpy(frame + *len, fuzz_data, fuzz_len);
        *len += fuzz_len;
    }
}

void fuzz_lora_frame(unsigned char *frame, size_t *len) {
    // LoRa-like PHY payload
    frame[0] = 0x40;  // PHDR
    frame[1] = rand() % 256;  // PHDR_CRC
    *len = 2;
    
    // Add fuzz data (limited to typical LoRa payload size)
    unsigned char *fuzz_data = fuzz_patterns[rand() % FUZZ_PATTERNS];
    size_t fuzz_len = strlen((char*)fuzz_data);
    if(fuzz_len > 64) fuzz_len = 64;
    
    memcpy(frame + *len, fuzz_data, fuzz_len);
    *len += fuzz_len;
    
    // Add CRC
    uint16_t crc = rand() % 65536;
    frame[*len] = (crc >> 8) & 0xFF;
    frame[*len + 1] = crc & 0xFF;
    *len += 2;
}

void fuzz_80211_frame(unsigned char *frame, size_t *len) {
    ieee80211_frame_t *wifi_frame = (ieee80211_frame_t*)frame;
    
    // Frame control (Management + Deauth)
    wifi_frame->frame_control[0] = 0x00;
    wifi_frame->frame_control[1] = 0x0C;
    
    // Duration
    wifi_frame->duration[0] = 0x00;
    wifi_frame->duration[1] = 0x00;
    
    // MAC addresses
    generate_random_mac(wifi_frame->addr1);  // Destination
    generate_random_mac(wifi_frame->addr2);  // Source
    generate_random_mac(wifi_frame->addr3);  // BSSID
    
    // Sequence control
    wifi_frame->sequence[0] = rand() % 256;
    wifi_frame->sequence[1] = rand() % 256;
    
    *len = sizeof(ieee80211_frame_t);
    
    // Add fuzz data as payload
    unsigned char *fuzz_data = fuzz_patterns[rand() % FUZZ_PATTERNS];
    size_t fuzz_len = strlen((char*)fuzz_data);
    
    if(*len + fuzz_len < MAX_FRAME_SIZE) {
        memcpy(frame + *len, fuzz_data, fuzz_len);
        *len += fuzz_len;
    }
}

int send_frame_pcap(pcap_t *handle, unsigned char *frame, size_t len) {
    if(pcap_sendpacket(handle, frame, len) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
        return -1;
    }
    return 0;
}

void usage(char *program_name) {
    printf("Usage: %s -p <protocol> -i <interface> -c <count>\n", program_name);
    printf("Protocols: zigbee, lora, 80211\n");
    printf("Example: %s -p 80211 -i wlan0 -c 100\n", program_name);
}

int main(int argc, char *argv[]) {
    char *protocol = NULL;
    char *interface = "wlan0";
    int count = 100;
    int opt;
    
    // Parse command line arguments
    while((opt = getopt(argc, argv, "p:i:c:h")) != -1) {
        switch(opt) {
            case 'p':
                protocol = optarg;
                break;
            case 'i':
                interface = optarg;
                break;
            case 'c':
                count = atoi(optarg);
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    if(protocol == NULL) {
        usage(argv[0]);
        return 1;
    }
    
    // Initialize pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open interface %s: %s\n", interface, errbuf);
        return 1;
    }
    
    printf("[*] Starting %s fuzzing on %s\n", protocol, interface);
    printf("[*] Sending %d frames\n", count);
    
    srand(time(NULL));
    
    for(int i = 0; i < count; i++) {
        unsigned char frame[MAX_FRAME_SIZE];
        size_t frame_len = 0;
        
        // Generate fuzzed frame based on protocol
        if(strcmp(protocol, "zigbee") == 0) {
            fuzz_zigbee_frame(frame, &frame_len);
        } else if(strcmp(protocol, "lora") == 0) {
            fuzz_lora_frame(frame, &frame_len);
        } else if(strcmp(protocol, "80211") == 0) {
            fuzz_80211_frame(frame, &frame_len);
        } else {
            fprintf(stderr, "Unknown protocol: %s\n", protocol);
            break;
        }
        
        // Send frame
        if(send_frame_pcap(handle, frame, frame_len) == 0) {
            if(i % 10 == 0) {
                printf("[+] Sent frame %d/%d\n", i, count);
            }
        }
        
        usleep(100000);  // 100ms delay
    }
    
    printf("[*] Fuzzing completed!\n");
    pcap_close(handle);
    return 0;
}
