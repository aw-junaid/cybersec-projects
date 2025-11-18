#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#endif

#define MAX_BEHAVIORS 20
#define MAX_BEHAVIOR_NAME 50
#define MAX_LOG_ENTRIES 1000

typedef struct {
    char name[MAX_BEHAVIOR_NAME];
    void (*function)();
    int risk_level;
} USBBehavior;

typedef struct {
    char event_type[50];
    char description[200];
    time_t timestamp;
} LogEntry;

typedef struct {
    LogEntry entries[MAX_LOG_ENTRIES];
    int count;
    int simulation_active;
} USBImplantSimulator;

// Global simulator instance
USBImplantSimulator simulator = {0};

// Behavior implementations
void simulate_file_creation() {
    printf("[SIMULATION] Creating test file...\n");
    
    FILE* file = fopen("usb_test_file.txt", "w");
    if (file) {
        fprintf(file, "USB Implant Simulation Test File\n");
        fprintf(file, "Created: %s", ctime(&(time_t){time(NULL)}));
        fprintf(file, "Purpose: Educational security testing\n");
        fclose(file);
        
        // Log the event
        if (simulator.count < MAX_LOG_ENTRIES) {
            LogEntry* entry = &simulator.entries[simulator.count++];
            strcpy(entry->event_type, "file_creation");
            strcpy(entry->description, "Created test file: usb_test_file.txt");
            entry->timestamp = time(NULL);
        }
    }
}

void simulate_file_deletion() {
    printf("[SIMULATION] Deleting test file...\n");
    
    if (remove("usb_test_file.txt") == 0) {
        // Log the event
        if (simulator.count < MAX_LOG_ENTRIES) {
            LogEntry* entry = &simulator.entries[simulator.count++];
            strcpy(entry->event_type, "file_deletion");
            strcpy(entry->description, "Deleted test file: usb_test_file.txt");
            entry->timestamp = time(NULL);
        }
    }
}

void simulate_process_creation() {
    printf("[SIMULATION] Creating test process...\n");
    
#ifdef _WIN32
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    // Create a harmless process (notepad)
    if (CreateProcess(NULL, "notepad", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        Sleep(2000); // Let it run for 2 seconds
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Log the event
        if (simulator.count < MAX_LOG_ENTRIES) {
            LogEntry* entry = &simulator.entries[simulator.count++];
            strcpy(entry->event_type, "process_creation");
            strcpy(entry->description, "Created process: notepad.exe");
            entry->timestamp = time(NULL);
        }
    }
#else
    // On Unix-like systems, use system call
    int result = system("sleep 2");
    if (result != -1) {
        if (simulator.count < MAX_LOG_ENTRIES) {
            LogEntry* entry = &simulator.entries[simulator.count++];
            strcpy(entry->event_type, "process_creation");
            strcpy(entry->description, "Executed system command: sleep 2");
            entry->timestamp = time(NULL);
        }
    }
#endif
}

void simulate_network_activity() {
    printf("[SIMULATION] Simulating network activity...\n");
    
#ifdef _WIN32
    system("ping 127.0.0.1 -n 2 > nul");
#else
    system("ping -c 2 127.0.0.1 > /dev/null 2>&1");
#endif

    // Log the event
    if (simulator.count < MAX_LOG_ENTRIES) {
        LogEntry* entry = &simulator.entries[simulator.count++];
        strcpy(entry->event_type, "network_activity");
        strcpy(entry->description, "Simulated network ping to localhost");
        entry->timestamp = time(NULL);
    }
}

void simulate_registry_operations() {
#ifdef _WIN32
    printf("[SIMULATION] Simulating registry operations...\n");
    
    HKEY hKey;
    const char* subkey = "Software\\USBImplantTest";
    
    // Create test registry key
    if (RegCreateKeyEx(HKEY_CURRENT_USER, subkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        const char* value = "Educational Test";
        RegSetValueEx(hKey, "TestValue", 0, REG_SZ, (BYTE*)value, strlen(value) + 1);
        RegCloseKey(hKey);
        
        // Log the event
        if (simulator.count < MAX_LOG_ENTRIES) {
            LogEntry* entry = &simulator.entries[simulator.count++];
            strcpy(entry->event_type, "registry_operation");
            strcpy(entry->description, "Created registry key: HKEY_CURRENT_USER\\Software\\USBImplantTest");
            entry->timestamp = time(NULL);
        }
        
        // Clean up
        RegDeleteKey(HKEY_CURRENT_USER, subkey);
    }
#endif
}

// Available behaviors
USBBehavior behaviors[] = {
    {"file_creation", simulate_file_creation, 2},
    {"file_deletion", simulate_file_deletion, 2},
    {"process_creation", simulate_process_creation, 3},
    {"network_activity", simulate_network_activity, 4},
    {"registry_operations", simulate_registry_operations, 5}
};

int behavior_count = sizeof(behaviors) / sizeof(behaviors[0]);

void list_behaviors() {
    printf("Available USB Implant Behaviors:\n");
    printf("================================\n");
    
    for (int i = 0; i < behavior_count; i++) {
        printf("%d. %s (Risk: %d/10)\n", i + 1, behaviors[i].name, behaviors[i].risk_level);
    }
    printf("\n");
}

void run_behavior(int index) {
    if (index < 0 || index >= behavior_count) {
        printf("Invalid behavior index\n");
        return;
    }
    
    printf("Executing behavior: %s\n", behaviors[index].name);
    behaviors[index].function();
    sleep(1); // Delay between behaviors
}

void run_simulation(int duration_seconds) {
    printf("Starting USB Implant Simulation for %d seconds...\n", duration_seconds);
    printf("FOR EDUCATIONAL PURPOSES ONLY\n\n");
    
    simulator.simulation_active = 1;
    time_t start_time = time(NULL);
    
    while (simulator.simulation_active && (time(NULL) - start_time) < duration_seconds) {
        // Randomly select and execute behaviors
        int behavior_index = rand() % behavior_count;
        run_behavior(behavior_index);
        
        // Check if we should continue
        if ((time(NULL) - start_time) >= duration_seconds) {
            break;
        }
    }
    
    simulator.simulation_active = 0;
    printf("\nSimulation completed.\n");
}

void stop_simulation() {
    simulator.simulation_active = 0;
    printf("Simulation stopped.\n");
}

void generate_report() {
    printf("\nUSB Implant Simulation Report\n");
    printf("=============================\n");
    printf("Total events logged: %d\n\n", simulator.count);
    
    for (int i = 0; i < simulator.count; i++) {
        LogEntry* entry = &simulator.entries[i];
        printf("Event %d:\n", i + 1);
        printf("  Type: %s\n", entry->event_type);
        printf("  Description: %s\n", entry->description);
        printf("  Time: %s", ctime(&entry->timestamp));
        printf("\n");
    }
    
    // Calculate statistics
    int event_types[10] = {0};
    for (int i = 0; i < simulator.count; i++) {
        // Simple type counting - in real implementation, use proper mapping
        for (int j = 0; j < behavior_count; j++) {
            if (strstr(simulator.entries[i].event_type, behaviors[j].name)) {
                event_types[j]++;
                break;
            }
        }
    }
    
    printf("Event Statistics:\n");
    for (int i = 0; i < behavior_count; i++) {
        printf("  %s: %d events\n", behaviors[i].name, event_types[i]);
    }
}

int main() {
    srand(time(NULL)); // Seed random number generator
    
    printf("USB Implant Simulator - C Implementation\n");
    printf("FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY\n\n");
    
    int choice;
    do {
        printf("1. List Behaviors\n");
        printf("2. Run Simulation (30 seconds)\n");
        printf("3. Run Simulation (Custom duration)\n");
        printf("4. Stop Simulation\n");
        printf("5. Generate Report\n");
        printf("6. Exit\n");
        printf("Choice: ");
        
        scanf("%d", &choice);
        
        switch (choice) {
            case 1:
                list_behaviors();
                break;
            case 2:
                run_simulation(30);
                break;
            case 3:
                printf("Enter duration in seconds: ");
                int duration;
                scanf("%d", &duration);
                run_simulation(duration);
                break;
            case 4:
                stop_simulation();
                break;
            case 5:
                generate_report();
                break;
            case 6:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice\n");
        }
        
    } while (choice != 6);
    
    return 0;
}
