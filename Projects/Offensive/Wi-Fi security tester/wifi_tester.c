/* wifi_tester.c — Educational Wi-Fi Security Analyzer (safe)
   Compile: gcc -o wifi_tester wifi_tester.c
   Run: sudo ./wifi_tester
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define BUF_SIZE 8192

void analyze_line(const char *line) {
    if (strstr(line, "Encryption key:off")) {
        printf("⚠️  Open network detected!\n");
    }
    if (strstr(line, "WEP")) {
        printf("⚠️  Weak WEP encryption found!\n");
    }
}

int main() {
    FILE *fp;
    char buf[BUF_SIZE];

    printf("Scanning Wi-Fi networks...\n");
    fp = popen("iwlist scan 2>/dev/null", "r");
    if (!fp) {
        perror("popen");
        return 1;
    }

    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "Cell ")) printf("\n--- Network ---\n");
        if (strstr(buf, "ESSID:")) {
            char *p = strchr(buf, '"');
            if (p) printf("SSID: %s\n", p+1);
        }
        if (strstr(buf, "Encryption key:") || strstr(buf, "IE: IEEE 802.11i")) {
            analyze_line(buf);
        }
        if (strstr(buf, "Quality=")) {
            printf("%s", buf);
        }
    }

    pclose(fp);
    printf("\nDone.\n");
    return 0;
}
