#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <time.h>

#define MAX_DEVICES 255
#define SCAN_DURATION 8  // seconds
#define MAX_SERVICES 50

typedef struct {
    char addr[19];  // XX:XX:XX:XX:XX:XX
    char name[248];
} bt_device;

typedef struct {
    char name[256];
    char protocol[32];
    int port;
    char service_id[64];
} bt_service;

// Basic device discovery
int discover_devices(bt_device devices[], int max_devices) {
    printf("[SCAN] Discovering Bluetooth devices...\n");
    
    inquiry_info *ii = NULL;
    int num_rsp, dev_id, sock, len, flags;
    int i;
    char addr[19] = {0};
    char name[248] = {0};
    
    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        perror("No Bluetooth device available");
        return -1;
    }
    
    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Could not open Bluetooth socket");
        return -1;
    }
    
    len = SCAN_DURATION;
    max_devices = max_devices > MAX_DEVICES ? MAX_DEVICES : max_devices;
    ii = (inquiry_info*)malloc(max_devices * sizeof(inquiry_info));
    
    num_rsp = hci_inquiry(dev_id, len, max_devices, NULL, &ii, flags);
    if (num_rsp < 0) {
        perror("HCI inquiry failed");
        free(ii);
        close(sock);
        return -1;
    }
    
    int found_devices = 0;
    for (i = 0; i < num_rsp; i++) {
        ba2str(&(ii+i)->bdaddr, addr);
        memset(name, 0, sizeof(name));
        
        if (hci_read_remote_name(sock, &(ii+i)->bdaddr, sizeof(name), 
                                name, 0) < 0) {
            strcpy(name, "[unknown]");
        }
        
        strncpy(devices[found_devices].addr, addr, sizeof(devices[found_devices].addr) - 1);
        strncpy(devices[found_devices].name, name, sizeof(devices[found_devices].name) - 1);
        
        printf("  Found: %s (%s)\n", name, addr);
        found_devices++;
    }
    
    free(ii);
    close(sock);
    
    printf("[SCAN] Found %d devices\n", found_devices);
    return found_devices;
}

// RFCOMM port scanning
void rfcomm_scan(const char *target_addr) {
    printf("[RFCOMM] Scanning ports 1-30 on %s...\n", target_addr);
    
    struct sockaddr_rc addr;
    int sock, port;
    bdaddr_t target_bdaddr;
    
    str2ba(target_addr, &target_bdaddr);
    
    for (port = 1; port <= 30; port++) {
        sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (sock < 0) {
            perror("Could not create RFCOMM socket");
            return;
        }
        
        memset(&addr, 0, sizeof(addr));
        addr.rc_family = AF_BLUETOOTH;
        addr.rc_bdaddr = target_bdaddr;
        addr.rc_channel = port;
        
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("  RFCOMM Port %d: OPEN\n", port);
            close(sock);
        } else {
            // Port is closed or filtered
            close(sock);
        }
    }
}

// L2CAP PSM scanning
void l2cap_scan(const char *target_addr) {
    printf("[L2CAP] Scanning PSM 1-100 on %s...\n", target_addr);
    
    struct sockaddr_l2 addr;
    int sock, psm;
    bdaddr_t target_bdaddr;
    
    str2ba(target_addr, &target_bdaddr);
    
    for (psm = 1; psm <= 100; psm++) {
        sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
        if (sock < 0) {
            perror("Could not create L2CAP socket");
            return;
        }
        
        memset(&addr, 0, sizeof(addr));
        addr.l2_family = AF_BLUETOOTH;
        addr.l2_bdaddr = target_bdaddr;
        addr.l2_psm = htobs(psm);
        
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("  L2CAP PSM %d: OPEN\n", psm);
            close(sock);
        } else {
            close(sock);
        }
    }
}

// Basic Bluetooth information gathering
void get_bluetooth_info() {
    printf("[INFO] Gathering Bluetooth adapter information...\n");
    
    int dev_id, sock;
    struct hci_dev_info di;
    
    dev_id = hci_get_route(NULL);
    if (dev_id < 0) {
        printf("  No Bluetooth adapter found\n");
        return;
    }
    
    sock = hci_open_dev(dev_id);
    if (sock < 0) {
        perror("Could not open HCI device");
        return;
    }
    
    if (hci_devinfo(dev_id, &di) == 0) {
        printf("  Adapter: %s\n", di.name);
        printf("  Address: %s\n", batostr(&di.bdaddr));
        printf("  Type: %s\n", (di.type == 0) ? "BR/EDR" : 
                              (di.type == 1) ? "AMP" : "Unknown");
        printf("  Flags: 0x%X\n", di.flags);
    }
    
    close(sock);
}

// Simple DoS test simulation (educational)
void simulate_dos_test(const char *target_addr) {
    printf("[DoS-SIM] Simulating connection flood on %s...\n", target_addr);
    printf("  This is for educational purposes only!\n");
    
    struct sockaddr_rc addr;
    bdaddr_t target_bdaddr;
    int sockets[5];
    int i, success_count = 0;
    
    str2ba(target_addr, &target_bdaddr);
    
    // Attempt multiple connections
    for (i = 0; i < 5; i++) {
        sockets[i] = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
        if (sockets[i] < 0) {
            printf("  Could not create socket %d\n", i+1);
            continue;
        }
        
        memset(&addr, 0, sizeof(addr));
        addr.rc_family = AF_BLUETOOTH;
        addr.rc_bdaddr = target_bdaddr;
        addr.rc_channel = 1;
        
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(sockets[i], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (connect(sockets[i], (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            printf("  Connection %d established\n", i+1);
            success_count++;
        } else {
            printf("  Connection %d failed\n", i+1);
            close(sockets[i]);
            sockets[i] = -1;
        }
    }
    
    // Keep connections open briefly
    printf("  Keeping %d connections open for 3 seconds...\n", success_count);
    sleep(3);
    
    // Cleanup
    for (i = 0; i < 5; i++) {
        if (sockets[i] >= 0) {
            close(sockets[i]);
        }
    }
    
    printf("  DoS simulation completed\n");
}

int main(int argc, char *argv[]) {
    printf("Bluetooth Protocol Tester - C Implementation\n");
    printf("============================================\n");
    
    if (argc < 2) {
        printf("Usage: %s [options]\n", argv[0]);
        printf("Options:\n");
        printf("  --scan              Scan for nearby devices\n");
        printf("  --target <addr>     Target Bluetooth address\n");
        printf("  --rfcomm-scan       Scan RFCOMM ports\n");
        printf("  --l2cap-scan        Scan L2CAP PSM ports\n");
        printf("  --info              Show adapter info\n");
        printf("  --dos-sim           Simulate DoS (educational)\n");
        printf("\nExample: %s --scan\n", argv[0]);
        printf("         %s --target XX:XX:XX:XX:XX:XX --rfcomm-scan\n", argv[0]);
        return 1;
    }
    
    bt_device devices[MAX_DEVICES];
    int device_count = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scan") == 0) {
            device_count = discover_devices(devices, MAX_DEVICES);
        }
        else if (strcmp(argv[i], "--info") == 0) {
            get_bluetooth_info();
        }
        else if (strcmp(argv[i], "--target") == 0) {
            if (i + 1 < argc) {
                char *target_addr = argv[++i];
                printf("Target: %s\n", target_addr);
                
                // Check what to do with target
                for (int j = i + 1; j < argc; j++) {
                    if (strcmp(argv[j], "--rfcomm-scan") == 0) {
                        rfcomm_scan(target_addr);
                    }
                    else if (strcmp(argv[j], "--l2cap-scan") == 0) {
                        l2cap_scan(target_addr);
                    }
                    else if (strcmp(argv[j], "--dos-sim") == 0) {
                        simulate_dos_test(target_addr);
                    }
                }
            } else {
                printf("Error: --target requires an address\n");
                return 1;
            }
        }
    }
    
    return 0;
}
