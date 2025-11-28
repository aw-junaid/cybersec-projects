/**
 * Safe Modbus/TCP Protocol Parser
 * FOR LAB USE ONLY - OFFLINE ANALYSIS ONLY
 * SAFETY: Never connect to real ICS systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>

#define MODBUS_TCP_HEADER_SIZE 7
#define MODBUS_PROTOCOL_ID 0

typedef struct {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t unit_id;
    uint8_t function_code;
    uint16_t start_address;
    uint16_t quantity;
    uint8_t data[256];
} modbus_pdu_t;

// Safety notice at startup
void print_safety_notice() {
    printf("=== SAFETY NOTICE ===\n");
    printf("This tool is for OFFLINE analysis only.\n");
    printf("Never use on production ICS/OT networks.\n");
    printf("Operate only in authorized lab environments.\n");
    printf("=====================\n\n");
}

json_t* parse_modbus_frame(const uint8_t* data, size_t len) {
    if (len < MODBUS_TCP_HEADER_SIZE) {
        return json_object();
    }
    
    modbus_pdu_t pdu;
    
    // Parse MBAP header
    pdu.transaction_id = (data[0] << 8) | data[1];
    pdu.protocol_id = (data[2] << 8) | data[3];
    pdu.length = (data[4] << 8) | data[5];
    pdu.unit_id = data[6];
    
    // Parse PDU
    if (len > MODBUS_TCP_HEADER_SIZE) {
        pdu.function_code = data[7];
        
        // Parse common function codes
        switch(pdu.function_code) {
            case 1:  // Read Coils
            case 2:  // Read Discrete Inputs
            case 3:  // Read Holding Registers
            case 4:  // Read Input Registers
                if (len >= MODBUS_TCP_HEADER_SIZE + 5) {
                    pdu.start_address = (data[8] << 8) | data[9];
                    pdu.quantity = (data[10] << 8) | data[11];
                }
                break;
            case 5:  // Write Single Coil
            case 6:  // Write Single Register
                if (len >= MODBUS_TCP_HEADER_SIZE + 5) {
                    pdu.start_address = (data[8] << 8) | data[9];
                    pdu.quantity = 1;
                }
                break;
            case 15: // Write Multiple Coils
            case 16: // Write Multiple Registers
                if (len >= MODBUS_TCP_HEADER_SIZE + 6) {
                    pdu.start_address = (data[8] << 8) | data[9];
                    pdu.quantity = (data[10] << 8) | data[11];
                }
                break;
        }
    }
    
    // Create JSON output
    json_t* root = json_object();
    json_object_set_new(root, "transaction_id", json_integer(pdu.transaction_id));
    json_object_set_new(root, "protocol_id", json_integer(pdu.protocol_id));
    json_object_set_new(root, "length", json_integer(pdu.length));
    json_object_set_new(root, "unit_id", json_integer(pdu.unit_id));
    json_object_set_new(root, "function_code", json_integer(pdu.function_code));
    json_object_set_new(root, "start_address", json_integer(pdu.start_address));
    json_object_set_new(root, "quantity", json_integer(pdu.quantity));
    
    // Add function code description
    const char* func_desc = "Unknown";
    switch(pdu.function_code) {
        case 1: func_desc = "Read Coils"; break;
        case 2: func_desc = "Read Discrete Inputs"; break;
        case 3: func_desc = "Read Holding Registers"; break;
        case 4: func_desc = "Read Input Registers"; break;
        case 5: func_desc = "Write Single Coil"; break;
        case 6: func_desc = "Write Single Register"; break;
        case 15: func_desc = "Write Multiple Coils"; break;
        case 16: func_desc = "Write Multiple Registers"; break;
    }
    json_object_set_new(root, "function_description", json_string(func_desc));
    
    return root;
}

int main(int argc, char* argv[]) {
    print_safety_notice();
    
    if (argc != 2) {
        printf("Usage: %s <pcap_file_or_hex_dump>\n", argv[0]);
        printf("SAFETY: This tool is for OFFLINE analysis only.\n");
        return 1;
    }
    
    printf("Parsing file: %s\n", argv[1]);
    printf("This is a stub implementation for demonstration.\n");
    printf("In full implementation, would parse PCAP and extract Modbus frames.\n");
    
    // Create sample output for demonstration
    json_t* root = json_object();
    json_object_set_new(root, "file", json_string(argv[1]));
    json_object_set_new(root, "frames_processed", json_integer(0));
    json_object_set_new(root, "warning", 
                       json_string("This is demo output - implement full PCAP parsing"));
    
    char* output = json_dumps(root, JSON_INDENT(2));
    printf("%s\n", output);
    
    free(output);
    json_decref(root);
    
    return 0;
}
