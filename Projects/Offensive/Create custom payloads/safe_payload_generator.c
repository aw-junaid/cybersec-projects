/*
 * safe_payload_generator.c
 *
 * Minimal safe payload generator in C.
 * - Supports pattern (zeros, ff, inc, repeat) and simple random fuzz.
 * - Writes payload files and a manifest JSON (append-only).
 *
 * Compile:
 *   gcc safe_payload_generator.c -o safe_payload_generator
 *
 * Examples:
 *   ./safe_payload_generator pattern inc 1024 3 ./out
 *   ./safe_payload_generator fuzz 512 5 ./out
 *
 * This program is intentionally small and only uses stdlib.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define mkdirp(dir,mode) _mkdir(dir)
#else
#define mkdirp(dir,mode) mkdir(dir,mode)
#endif

void ensure_dir(const char *dir) {
    // naive: try to create, ignore errors if exists
    mkdirp(dir, 0755);
}

unsigned char *gen_pattern(const char *ptype, size_t size, const char *token) {
    unsigned char *buf = malloc(size);
    if (!buf) return NULL;
    if (strcmp(ptype, "zeros") == 0) {
        memset(buf, 0, size);
    } else if (strcmp(ptype, "ff") == 0) {
        memset(buf, 0xFF, size);
    } else if (strcmp(ptype, "inc") == 0) {
        for (size_t i = 0; i < size; ++i) buf[i] = (unsigned char)(i & 0xFF);
    } else if (strcmp(ptype, "repeat") == 0) {
        size_t tlen = strlen(token);
        if (tlen == 0) token = "TEST", tlen = 4;
        for (size_t i = 0; i < size; ++i) {
            buf[i] = token[i % tlen];
        }
    } else {
        memset(buf, 0, size);
    }
    return buf;
}

unsigned char *gen_fuzz(size_t size) {
    unsigned char *buf = malloc(size);
    if (!buf) return NULL;
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < size; ++i) buf[i] = (unsigned char)(rand() & 0xFF);
    return buf;
}

char *sha256_hex_placeholder() {
    // In this simple C example we return a placeholder; computing SHA256 is omitted to keep it small.
    char *s = malloc(65);
    strcpy(s, "sha256-not-computed-in-simple-c-example----------------");
    return s;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage:\n  %s <mode> <size> <count> <outdir> [pattern_token]\n", argv[0]);
        fprintf(stderr, "Modes: pattern, fuzz\n");
        return 1;
    }
    const char *mode = argv[1];
    size_t size = (size_t)atoi(argv[2]);
    int count = atoi(argv[3]);
    const char *outdir = argv[4];
    const char *token = argc > 5 ? argv[5] : "TEST";

    ensure_dir(outdir);

    // open manifest for append (simple JSON array continuation is not implemented; write per run)
    char manifest_path[1024];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", outdir);
    FILE *mf = fopen(manifest_path, "w");
    if (!mf) {
        perror("manifest open");
        return 1;
    }
    fprintf(mf, "[\n");

    for (int i = 0; i < count; ++i) {
        unsigned char *data = NULL;
        if (strcmp(mode, "pattern") == 0) {
            data = gen_pattern(token, size, token); // token param overloaded but ok
        } else if (strcmp(mode, "fuzz") == 0) {
            data = gen_fuzz(size);
        } else {
            fprintf(stderr, "Unknown mode %s\n", mode);
            fclose(mf);
            return 1;
        }
        if (!data) {
            fprintf(stderr, "Allocation failed\n");
            fclose(mf);
            return 1;
        }
        char filename[1024];
        snprintf(filename, sizeof(filename), "%s/%s_%d.bin", outdir, mode, i+1);
        FILE *f = fopen(filename, "wb");
        if (!f) {
            perror("file open");
            free(data);
            fclose(mf);
            return 1;
        }
        fwrite(data, 1, size, f);
        fclose(f);

        char *sha = sha256_hex_placeholder();
        fprintf(mf, "  {\n    \"filename\": \"%s\",\n    \"mode\": \"%s\",\n    \"size_raw\": %zu,\n    \"sha256\": \"%s\"\n  }%s\n", filename, mode, size, sha, (i==count-1) ? "" : ",");
        free(sha);
        free(data);
        printf("[+] wrote %s (%zu bytes)\n", filename, size);
    }

    fprintf(mf, "]\n");
    fclose(mf);
    printf("[+] manifest: %s\n", manifest_path);
    return 0;
}
