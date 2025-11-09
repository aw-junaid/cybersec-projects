/*
subenum.c — Basic Subdomain Enumeration Tool
Usage:
  ./subenum example.com wordlist.txt
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <domain> <wordlist>\n", argv[0]);
        return 1;
    }

    char *domain = argv[1];
    FILE *f = fopen(argv[2], "r");
    if (!f) {
        perror("wordlist");
        return 1;
    }

    char sub[256], full[512];
    struct hostent *he;
    struct in_addr **addr_list;

    printf("[+] Enumerating subdomains for %s\n", domain);
    while (fgets(sub, sizeof(sub), f)) {
        sub[strcspn(sub, "\n")] = 0;  // remove newline
        snprintf(full, sizeof(full), "%s.%s", sub, domain);
        he = gethostbyname(full);
        if (he) {
            addr_list = (struct in_addr **)he->h_addr_list;
            for (int i = 0; addr_list[i] != NULL; i++) {
                printf("[FOUND] %s -> %s\n", full, inet_ntoa(*addr_list[i]));
            }
        }
    }
    fclose(f);
    return 0;
}
