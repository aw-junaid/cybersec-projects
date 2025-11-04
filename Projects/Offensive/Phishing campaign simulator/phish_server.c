/* phish_server.c - minimal blocking HTTP server (lab-only)
   - Serves files from ./www
   - Logs requests to ./logs/phish_c.log
   Compile:
     gcc -o phish_server phish_server.c
   Run:
     mkdir -p www logs
     # create a sample index.html or landing page in www/
     ./phish_server 8080
   Open: http://127.0.0.1:8080/
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>

#define WWW_DIR "www"
#define LOG_FILE "logs/phish_c.log"
#define BUFSIZE 8192

void log_request(const char *client, const char *method, const char *path) {
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm);
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    fprintf(f, "%s %s %s %s\n", ts, client, method, path);
    fclose(f);
}

void serve_file(int fd, const char *path) {
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", WWW_DIR, path[0]=='/'?path+1:path);
    // default to index.html if directory or empty
    struct stat st;
    if (stat(full, &st) == -1 || S_ISDIR(st.st_mode)) {
        // try index.html
        snprintf(full, sizeof(full), "%s/index.html", WWW_DIR);
        if (stat(full, &st) == -1) {
            const char *notfound = "HTTP/1.1 404 Not Found\r\nContent-Length:13\r\n\r\n404 Not Found\n";
            send(fd, notfound, strlen(notfound), 0);
            return;
        }
    }
    FILE *f = fopen(full, "rb");
    if (!f) {
        const char *err = "HTTP/1.1 500 Internal Server Error\r\nContent-Length:21\r\n\r\n500 file read error\n";
        send(fd, err, strlen(err), 0);
        return;
    }
    // get size
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char hdr[256];
    snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Length:%ld\r\n\r\n", sz);
    send(fd, hdr, strlen(hdr), 0);
    // send file
    char buf[4096];
    size_t r;
    while ((r = fread(buf,1,sizeof(buf),f)) > 0) {
        send(fd, buf, r, 0);
    }
    fclose(f);
}

int main(int argc, char **argv) {
    int port = 8080;
    if (argc >= 2) port = atoi(argv[1]);
    mkdir("www", 0755);
    mkdir("logs", 0755);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    int opt = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) { perror("bind"); close(s); return 1; }
    if (listen(s, 10) < 0) { perror("listen"); close(s); return 1; }

    printf("[+] phish_server listening on 0.0.0.0:%d (serving ./www)\n", port);
    while (1) {
        struct sockaddr_in cli; socklen_t len = sizeof(cli);
        int fd = accept(s, (struct sockaddr*)&cli, &len);
        if (fd < 0) continue;
        char client[64]; inet_ntop(AF_INET, &cli.sin_addr, client, sizeof(client));
        // read request (simple)
        char buf[BUFSIZE];
        ssize_t n = recv(fd, buf, sizeof(buf)-1, 0);
        if (n <= 0) { close(fd); continue;}
        buf[n] = 0;
        // parse very simply: first line METHOD PATH
        char method[16], path[512];
        if (sscanf(buf, "%15s %511s", method, path) < 2) {
            close(fd); continue;
        }
        log_request(client, method, path);
        // if POST to /submit, log and respond with friendly page (do NOT store body)
        if (strcmp(method, "POST")==0 && strcmp(path, "/submit")==0) {
            // respond with success (do not parse or store body—avoid collecting creds)
            const char *resp = "HTTP/1.1 200 OK\r\nContent-Length:44\r\n\r\nThanks — this was a local training simulation.\n";
            send(fd, resp, strlen(resp), 0);
            close(fd);
            continue;
        }
        // otherwise serve file
        serve_file(fd, path);
        close(fd);
    }
    close(s);
    return 0;
}
