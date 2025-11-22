#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define MEMORY_SIZE 1024
#define REGISTER_COUNT 16
#define MAX_FAULT_INJECTIONS 1000

typedef enum {
    FAULT_VOLTAGE_GLITCH,
    FAULT_CLOCK_GLITCH,
    FAULT_EM_PULSE,
    FAULT_LASER,
    FAULT_TEMPERATURE,
    FAULT_RADIATION
} fault_type_t;

typedef struct {
    fault_type_t type;
    float intensity;
    float duration;
    float timing;
    int location_x;
    int location_y;
} fault_parameters_t;

typedef struct {
    unsigned int registers[REGISTER_COUNT];
    unsigned char memory[MEMORY_SIZE];
    unsigned char security_flags;
    unsigned int program_counter;
    unsigned int stack_pointer;
} device_state_t;

typedef struct {
    fault_parameters_t params;
    int successful;
    char description[256];
    device_state_t state_before;
    device_state_t state_after;
} fault_result_t;

typedef struct {
    device_state_t current_state;
    fault_result_t results[MAX_FAULT_INJECTIONS];
    int result_count;
    int total_injections;
} fault_lab_t;

void initialize_device(device_state_t* device) {
    memset(device, 0, sizeof(device_state_t));
    
    // Initialize with test values
    for (int i = 0; i < REGISTER_COUNT; i++) {
        device->registers[i] = i * 0x11111111;
    }
    
    // Initialize memory with pattern
    for (int i = 0; i < MEMORY_SIZE; i++) {
        device->memory[i] = (i % 256);
    }
    
    device->program_counter = 0x00000000;
    device->stack_pointer = 0x20001000;
    device->security_flags = 0xFF; // All security enabled
}

void simulate_operation(device_state_t* device, int cycles) {
    printf("Simulating %d operation cycles...\n", cycles);
    
    for (int i = 0; i < cycles; i++) {
        // Simple simulation: increment PC and modify registers
        device->program_counter += 4;
        
        // Simulate register operations
        device->registers[0] = device->program_counter;
        device->registers[1] = device->registers[1] + 1;
        
        // Simulate memory access
        int mem_addr = device->program_counter % MEMORY_SIZE;
        device->memory[mem_addr] = (device->memory[mem_addr] + 1) % 256;
    }
}

float calculate_success_probability(fault_parameters_t params) {
    float base_rates[] = {0.3, 0.4, 0.25, 0.6, 0.15, 0.2};
    return base_rates[params.type] * params.intensity;
}

void simulate_fault_effect(device_state_t* device, fault_parameters_t params, fault_result_t* result) {
    float success_prob = calculate_success_probability(params);
    result->successful = (rand() / (float)RAND_MAX) < success_prob;
    
    if (!result->successful) {
        strcpy(result->description, "Fault injection failed");
        return;
    }
    
    // Apply fault effects based on type
    switch (params.type) {
        case FAULT_VOLTAGE_GLITCH:
            // Corrupt a random register
            {
                int reg = rand() % REGISTER_COUNT;
                unsigned int old_val = device->registers[reg];
                unsigned int fault_mask = (1 << (rand() % 32));
                device->registers[reg] ^= fault_mask;
                snprintf(result->description, sizeof(result->description),
                        "Voltage glitch: Register R%d corrupted (0x%08X -> 0x%08X)",
                        reg, old_val, device->registers[reg]);
            }
            break;
            
        case FAULT_CLOCK_GLITCH:
            // Cause instruction skip
            {
                int skip_amount = 4 * (1 + rand() % 3); // Skip 1-3 instructions
                device->program_counter += skip_amount;
                snprintf(result->description, sizeof(result->description),
                        "Clock glitch: Skipped %d bytes at PC", skip_amount);
            }
            break;
            
        case FAULT_EM_PULSE:
            // Multiple memory corruptions
            {
                int num_corruptions = 1 + rand() % 3;
                for (int i = 0; i < num_corruptions; i++) {
                    int addr = rand() % MEMORY_SIZE;
                    device->memory[addr] ^= (1 << (rand() % 8));
                }
                snprintf(result->description, sizeof(result->description),
                        "EM pulse: %d memory locations corrupted", num_corruptions);
            }
            break;
            
        case FAULT_LASER:
            // Precise fault - disable security
            if (params.intensity > 0.5) {
                device->security_flags = 0x00; // Disable all security
                snprintf(result->description, sizeof(result->description),
                        "Laser fault: Security disabled (flags: 0x%02X)", device->security_flags);
            } else {
                strcpy(result->description, "Laser fault: Insufficient intensity");
                result->successful = 0;
            }
            break;
            
        default:
            strcpy(result->description, "Fault type not implemented");
            result->successful = 0;
            break;
    }
}

void inject_fault(fault_lab_t* lab, fault_parameters_t params) {
    if (lab->result_count >= MAX_FAULT_INJECTIONS) {
        printf("Maximum fault injections reached\n");
        return;
    }
    
    fault_result_t* result = &lab->results[lab->result_count];
    result->params = params;
    
    // Save state before fault
    result->state_before = lab->current_state;
    
    // Simulate fault effect
    simulate_fault_effect(&lab->current_state, params, result);
    
    // Save state after fault
    if (result->successful) {
        result->state_after = lab->current_state;
    }
    
    lab->result_count++;
    lab->total_injections++;
    
    printf("Fault injection: %s - %s\n", 
           result->successful ? "SUCCESS" : "FAILED", 
           result->description);
}

void print_statistics(fault_lab_t* lab) {
    printf("\n=== Fault Injection Statistics ===\n");
    printf("Total injections: %d\n", lab->total_injections);
    printf("Successful: %d\n", lab->result_count);
    
    int type_counts[6] = {0};
    int type_success[6] = {0};
    
    for (int i = 0; i < lab->result_count; i++) {
        fault_type_t type = lab->results[i].params.type;
        type_counts[type]++;
        if (lab->results[i].successful) {
            type_success[type]++;
        }
    }
    
    const char* type_names[] = {
        "Voltage Glitch", "Clock Glitch", "EM Pulse", 
        "Laser", "Temperature", "Radiation"
    };
    
    printf("\nSuccess rates by fault type:\n");
    for (int i = 0; i < 6; i++) {
        if (type_counts[i] > 0) {
            float rate = (float)type_success[i] / type_counts[i] * 100;
            printf("  %-15s: %d/%d (%.1f%%)\n", 
                   type_names[i], type_success[i], type_counts[i], rate);
        }
    }
}

void demonstrate_dfa() {
    printf("\n=== Differential Fault Analysis Demo ===\n");
    
    // Simplified DFA demonstration
    unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char plaintext[16] = "test_plaintext!";
    unsigned char normal_ciphertext[16];
    unsigned char faulty_ciphertext[16];
    
    printf("Performing simplified DFA simulation...\n");
    
    // Simulate multiple fault injections
    int successful_faults = 0;
    for (int i = 0; i < 100; i++) {
        // Simulate fault injection during encryption
        if (rand() % 100 < 30) { // 30% success rate
            successful_faults++;
            
            // In real DFA, we would analyze the differential here
            // For demo, just count successful injections
        }
    }
    
    printf("Successful fault injections: %d/100\n", successful_faults);
    printf("DFA would use these to extract key bytes statistically\n");
}

int main() {
    srand(time(NULL));
    
    printf("Hardware Fault Injection Lab - C Implementation\n");
    printf("==============================================\n");
    
    fault_lab_t lab;
    memset(&lab, 0, sizeof(fault_lab_t));
    initialize_device(&lab.current_state);
    
    // Simulate normal operation
    simulate_operation(&lab.current_state, 1000);
    
    // Perform various fault injections
    printf("\nPerforming fault injection experiments...\n");
    
    fault_parameters_t params;
    
    // Voltage glitch tests
    for (int i = 0; i < 5; i++) {
        params.type = FAULT_VOLTAGE_GLITCH;
        params.intensity = 0.2 + (i * 0.2);
        params.duration = 5.0;
        params.timing = 50.0;
        inject_fault(&lab, params);
    }
    
    // Clock glitch tests
    for (int i = 0; i < 5; i++) {
        params.type = FAULT_CLOCK_GLITCH;
        params.intensity = 0.3 + (i * 0.15);
        params.duration = 2.0;
        params.timing = 25.0;
        inject_fault(&lab, params);
    }
    
    // EM pulse tests
    for (int i = 0; i < 3; i++) {
        params.type = FAULT_EM_PULSE;
        params.intensity = 0.5 + (i * 0.2);
        params.duration = 10.0;
        params.timing = 75.0;
        inject_fault(&lab, params);
    }
    
    // Laser fault tests
    for (int i = 0; i < 3; i++) {
        params.type = FAULT_LASER;
        params.intensity = 0.6 + (i * 0.2);
        params.duration = 1.0;
        params.timing = 10.0;
        params.location_x = rand() % 100;
        params.location_y = rand() % 100;
        inject_fault(&lab, params);
    }
    
    // Print statistics
    print_statistics(&lab);
    
    // Demonstrate DFA
    demonstrate_dfa();
    
    printf("\nExperiment complete!\n");
    
    return 0;
}
