/*
Benign Rootkit Simulator (C version)
- Sandbox-only educational simulation
- Create/remove hidden files
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#define SANDBOX_ENV "ROOTKIT_SANDBOX"

int safety_check() {
    char *env = getenv(SANDBOX_ENV);
    if (!env || strcmp(env,"1") != 0) {
        printf("[!] ROOTKIT_SANDBOX not set. Abort.\n");
        return 0;
    }
    return 1;
}

void create_hidden_file(const char *sandbox, const char *name, const char *content) {
    char path[512];
    snprintf(path, sizeof(path), "%s/.rk_hidden_%s", sandbox, name);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs(content, f);
    fclose(f);
    printf("[+] Created hidden file: %s\n", path);
}

void cleanup_hidden_files(const char *sandbox) {
    char path[512];
    snprintf(path, sizeof(path), "%s/", sandbox);
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strstr(entry->d_name, ".rk_hidden_")) {
            snprintf(path, sizeof(path), "%s/%s", sandbox, entry->d_name);
            remove(path);
            printf("[-] Removed %s\n", path);
        }
    }
    closedir(d);
}

int main() {
    if (!safety_check()) return 1;
    char sandbox[256];
    printf("Enter sandbox dir: ");
    scanf("%255s", sandbox);

    int choice;
    printf("Run simulation or cleanup? (1=run,2=cleanup): ");
    scanf("%d",&choice);

    if (choice == 1) {
        create_hidden_file(sandbox, "file1.txt", "Secret data");
        create_hidden_file(sandbox, "file2.log", "Simulated log");
    } else if (choice == 2) {
        cleanup_hidden_files(sandbox);
    } else {
        printf("Invalid choice.\n");
    }
    return 0;
}
