/* sim_client.c
   Compile: gcc -o sim_client sim_client.c
   Usage: ./sim_client [host] [port] [token]
   Example: ./sim_client 127.0.0.1 9000 labtoken
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int send_msg(int fd, const char *s) {
    uint32_t n = htonl((uint32_t)strlen(s));
    if (write(fd, &n, 4) != 4) return -1;
    if (write(fd, s, strlen(s)) != (ssize_t)strlen(s)) return -1;
    return 0;
}

char *recv_msg(int fd) {
    uint32_t n;
    if (read(fd, &n, 4) != 4) return NULL;
    n = ntohl(n);
    char *buf = malloc(n+1);
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf+got, n-got);
        if (r <= 0) { free(buf); return NULL; }
        got += r;
    }
    buf[n] = 0;
    return buf;
}

int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 9000;
    const char *token = (argc > 3) ? argv[3] : "labtoken";

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, host, &sa.sin_addr);
    sa.sin_port = htons(port);
    if (connect(sock, (struct sockaddr*)&sa, sizeof(sa)) != 0) { perror("connect"); return 1; }
    char authline[512];
    snprintf(authline, sizeof(authline), "AUTH %s", token);
    send_msg(sock, authline);
    char *resp = recv_msg(sock);
    if (!resp) { fprintf(stderr,"no response\n"); close(sock); return 1; }
    if (strcmp(resp, "AUTH_OK") != 0) { fprintf(stderr,"auth failed: %s\n", resp); free(resp); close(sock); return 1; }
    free(resp);
    char *notice = recv_msg(sock);
    if (notice) { printf("[server] %s\n", notice); free(notice); }
    char line[1024];
    while (1) {
        printf("sim-shell> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        line[strcspn(line, "\n")] = 0;
        if (strcmp(line, "exit") == 0) { send_msg(sock, "exit"); break; }
        send_msg(sock, line);
        char *out = recv_msg(sock);
        if (!out) break;
        printf("%s\n", out);
        free(out);
    }
    close(sock);
    return 0;
}
