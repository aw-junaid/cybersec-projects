/* ransom_sim_min.c - Minimal SAFE ransomware simulator (lab-only)
   Compile: gcc -o ransom_sim_min ransom_sim_min.c
   Usage: SIM_RUN_ALLOWED=1 ./ransom_sim_min /tmp/sandbox_sim_example
   Safety: Refuses to run unless path contains "sandbox_sim" and env var is set.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char KEY[] = "sim_k3y";
static const size_t KEYLEN = 6;

int check_safety(const char *path) {
    char *env = getenv("SIM_RUN_ALLOWED");
    if (!env || strcmp(env, "1") != 0) {
        fprintf(stderr, "SIM_RUN_ALLOWED must be set to 1\n");
        return 0;
    }
    if (!strstr(path, "sandbox_sim")) {
        fprintf(stderr, "sandbox path must include 'sandbox_sim'\n");
        return 0;
    }
    return 1;
}

void xor_transform(unsigned char *buf, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        buf[i] ^= KEY[i % KEYLEN];
    }
}

int process_file(const char *dir, const char *name) {
    char path[1024], out[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    snprintf(out, sizeof(out), "%s/%s.encsim", dir, name);

    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0 || sz > 5*1024*1024) { fclose(f); return 0; } // safety size cap
    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return 0; }
    fread(buf, 1, sz, f);
    fclose(f);

    xor_transform(buf, sz);

    // write out
    FILE *g = fopen(out, "wb");
    if (!g) { free(buf); return 0; }
    fwrite(buf, 1, sz, g);
    fclose(g);
    free(buf);
    printf("WROTE %s\n", out);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s /path/to/sandbox_sim\n", argv[0]); return 1; }
    if (!check_safety(argv[1])) return 2;

    DIR *d = opendir(argv[1]);
    if (!d) { perror("opendir"); return 3; }
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_type != DT_REG) continue;
        // skip artifacts
        if (strstr(ent->d_name, ".encsim")) continue;
        // only .txt or .sample for safety
        const char *dot = strrchr(ent->d_name, '.');
        if (!dot) continue;
        if (strcmp(dot, ".txt") != 0 && strcmp(dot, ".sample") != 0) continue;
        process_file(argv[1], ent->d_name);
    }
    closedir(d);
    // write a ransom note
    char note[1024];
    snprintf(note, sizeof(note), "%s/README_RECOVER.txt", argv[1]);
    FILE *n = fopen(note, "w");
    if (n) {
        fputs("SIMULATOR: files transformed for lab analysis. Use the simulator revert tool.\n", n);
        fclose(n);
        printf("WROTE %s\n", note);
    }
    return 0;
}
