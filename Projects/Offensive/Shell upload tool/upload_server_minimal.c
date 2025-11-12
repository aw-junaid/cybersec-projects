/*
 upload_server_minimal.c - Minimal upload server for lab (no HTTP)
 Compile: gcc -o upload_server_minimal upload_server_minimal.c
 Usage: ./upload_server_minimal [port] [token]
 Protocol:
  - client connects
  - client sends token length (uint16_t network), token bytes
  - server replies OK/ERR (1 byte: 0x00=ERR, 0x01=OK)
  - client sends filename_len (uint16_t), filename bytes (no paths)
  - client sends content_len (uint64_t network), then content bytes
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BACKLOG 5
#define MAX_TOKEN 256
#define MAX_NAME 256
#define UPLOAD_DIR "uploads"

ssize_t read_n(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return got;
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 9001;
    const char *token = (argc > 2) ? argv[2] : "labtoken";

    mkdir(UPLOAD_DIR, 0700);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    bind(ls, (struct sockaddr*)&sa, sizeof(sa));
    listen(ls, BACKLOG);
    printf("Minimal upload server listening on 127.0.0.1:%d token='%s'\n", port, token);

    while (1) {
        int c = accept(ls, NULL, NULL);
        if (c < 0) continue;

        // read token length (uint16_t)
        uint16_t tlen;
        if (read_n(c, &tlen, 2) <= 0) { close(c); continue; }
        tlen = ntohs(tlen);
        if (tlen == 0 || tlen > MAX_TOKEN) { close(c); continue; }
        char tbuf[MAX_TOKEN+1];
        if (read_n(c, tbuf, tlen) <= 0) { close(c); continue; }
        tbuf[tlen] = 0;
        if (strcmp(tbuf, token) != 0) {
            uint8_t resp = 0x00; write(c, &resp, 1); close(c); continue;
        }
        uint8_t resp = 0x01; write(c, &resp, 1);

        // filename
        uint16_t nlen;
        if (read_n(c, &nlen, 2) <= 0) { close(c); continue; }
        nlen = ntohs(nlen);
        if (nlen == 0 || nlen > MAX_NAME) { close(c); continue; }
        char name[MAX_NAME+1];
        if (read_n(c, name, nlen) <= 0) { close(c); continue; }
        name[nlen] = 0;
        // sanitize: keep only basename characters (letters, digits, _ . -)
        char clean[MAX_NAME+1]; int ci=0;
        for (int i=0; name[i] && ci < MAX_NAME; ++i) {
            char ch = name[i];
            if ((ch >= 'a' && ch <= 'z') || (ch>='A'&&ch<='Z') || (ch>='0'&&ch<='9') || ch=='.' || ch=='_' || ch=='-')
                clean[ci++] = ch;
        }
        if (ci==0) { close(c); continue; }
        clean[ci] = 0;
        char dest[512];
        snprintf(dest, sizeof(dest), "%s/%s.safe", UPLOAD_DIR, clean);

        // content length (uint64_t)
        uint64_t clen_net;
        if (read_n(c, &clen_net, 8) <= 0) { close(c); continue; }
        uint64_t clen = be64toh(clen_net);
        if (clen > (10ULL * 1024 * 1024)) { close(c); continue; } // 10MB cap

        int fd = open(dest ".tmp", O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (fd < 0) { close(c); continue; }

        uint64_t remaining = clen;
        char buf[8192];
        while (remaining) {
            size_t toread = remaining > sizeof(buf) ? sizeof(buf) : (size_t)remaining;
            ssize_t r = read_n(c, buf, toread);
            if (r <= 0) { close(fd); unlink(dest ".tmp"); close(c); goto cont_loop; }
            write(fd, buf, r);
            remaining -= r;
        }
        fsync(fd);
        close(fd);
        rename(dest ".tmp", dest);
        printf("Stored %s (%llu bytes)\n", dest, (unsigned long long)clen);
        cont_loop:
        close(c);
    }

    close(ls);
    return 0;
}
