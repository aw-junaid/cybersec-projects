/* sim_server.c - Simple Reverse Shell Simulator (C)
   Safe: does NOT execute system commands.
   Compile: gcc -o sim_server sim_server.c
   Usage: ./sim_server [port] [token]
   Example: ./sim_server 9000 labtoken
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BACKLOG 5
#define BUF_SIZE 4096

// helpers: send length-prefixed line
int send_msg(int fd, const char *s) {
    uint32_t n = htonl((uint32_t)strlen(s));
    if (write(fd, &n, 4) != 4) return -1;
    if (write(fd, s, strlen(s)) != (ssize_t)strlen(s)) return -1;
    return 0;
}

char *recv_msg(int fd) {
    uint32_t n;
    ssize_t r = read(fd, &n, 4);
    if (r <= 0) return NULL;
    n = ntohl(n);
    if (n == 0) return strdup("");
    char *buf = malloc(n+1);
    size_t got = 0;
    while (got < n) {
        ssize_t rr = read(fd, buf+got, n-got);
        if (rr <= 0) { free(buf); return NULL;}
        got += rr;
    }
    buf[n] = 0;
    return buf;
}

// very small handler that returns canned outputs
void handle_command_simple(int client, const char *cmd) {
    if (strcmp(cmd, "whoami") == 0) {
        send_msg(client, "student");
    } else if (strcmp(cmd, "uname") == 0) {
        send_msg(client, "Linux lab-sim 5.10.0");
    } else if (strncmp(cmd, "echo ", 5) == 0) {
        send_msg(client, cmd + 5);
    } else if (strcmp(cmd, "date") == 0) {
        time_t t = time(NULL);
        char tmp[128];
        strftime(tmp, sizeof(tmp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
        send_msg(client, tmp);
    } else if (strcmp(cmd, "help") == 0) {
        send_msg(client, "Available: whoami, uname, echo, date, help");
    } else {
        send_msg(client, "Unknown command in simulator");
    }
}

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 9000;
    const char *token = (argc > 2) ? argv[2] : "labtoken";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // bind to localhost by default
    sa.sin_port = htons(port);
    if (bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    listen(sock, BACKLOG);
    printf("sim_server listening on 127.0.0.1:%d token='%s'\n", port, token);
    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) { perror("accept"); continue; }
        char *auth = recv_msg(client);
        if (!auth) { close(client); continue; }
        if (strncmp(auth, "AUTH ", 5) != 0 || strcmp(auth + 5, token) != 0) {
            send_msg(client, "AUTH_FAIL");
            free(auth);
            close(client);
            continue;
        }
        send_msg(client, "AUTH_OK");
        send_msg(client, "NOTICE: Authenticated. SIMULATOR only.");
        free(auth);
        // interactive: receive commands
        while (1) {
            char *cmd = recv_msg(client);
            if (!cmd) break;
            if (strcmp(cmd, "exit") == 0) { free(cmd); break; }
            handle_command_simple(client, cmd);
            free(cmd);
        }
        close(client);
    }
    close(sock);
    return 0;
}
