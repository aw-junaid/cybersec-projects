/* sniffer.c - simple libpcap sniffer + analyzer
   Compile:
     sudo apt install -y libpcap-dev
     gcc -o sniffer sniffer.c -lpcap
   Run:
     sudo ./sniffer -i eth0 -f "tcp and port 80" -w capture.pcap -c 0
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <signal.h>
#include <time.h>

#define MAX_TOP 32

static volatile int keep_running = 1;
static pcap_dumper_t *dumper = NULL;
static unsigned long total_pkts = 0;
static unsigned long total_bytes = 0;

typedef struct talker {
    uint32_t ip;
    unsigned long cnt;
} talker_t;

talker_t talkers[MAX_TOP];
int talkers_count = 0;

void stop_handler(int signum) {
    (void)signum;
    keep_running = 0;
}

/* simple update top talkers (unsophisticated linear insert) */
void update_talkers(uint32_t ip) {
    for (int i = 0; i < talkers_count; ++i) {
        if (talkers[i].ip == ip) {
            talkers[i].cnt++;
            return;
        }
    }
    if (talkers_count < MAX_TOP) {
        talkers[talkers_count].ip = ip;
        talkers[talkers_count].cnt = 1;
        talkers_count++;
        return;
    }
    // replace smallest
    int min_idx = 0;
    for (int i = 1; i < talkers_count; ++i)
        if (talkers[i].cnt < talkers[min_idx].cnt) min_idx = i;
    talkers[min_idx].ip = ip;
    talkers[min_idx].cnt = 1;
}

/* packet callback called by pcap_loop */
void pkt_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    total_pkts++;
    total_bytes += h->len;
    if (dumper) pcap_dump((u_char*)dumper, h, bytes);

    // Attempt to parse IPv4 header (assume Ethernet linktype with 14 byte header)
    if (h->len < 34) return;
    const u_char *ip_start = bytes + 14;
    struct ip *ip = (struct ip*)ip_start;
    if (ip->ip_v == 4) {
        uint32_t src = ip->ip_src.s_addr;
        update_talkers(src);
    }

    if (total_pkts % 100 == 0) {
        printf("\rPkts: %lu  Bytes: %lu", total_pkts, total_bytes);
        fflush(stdout);
    }
}

void print_summary() {
    printf("\n\n=== Summary ===\n");
    printf("Total packets: %lu\n", total_pkts);
    printf("Total bytes: %lu\n", total_bytes);
    printf("Top talkers (approx):\n");
    // sort talkers array descending
    for (int i = 0; i < talkers_count; ++i) {
        for (int j = i+1; j < talkers_count; ++j) {
            if (talkers[j].cnt > talkers[i].cnt) {
                talker_t t = talkers[i]; talkers[i] = talkers[j]; talkers[j]=t;
            }
        }
    }
    for (int i = 0; i < talkers_count; ++i) {
        struct in_addr a; a.s_addr = talkers[i].ip;
        printf("  %s : %lu\n", inet_ntoa(a), talkers[i].cnt);
    }
    printf("================\n");
}

int main(int argc, char **argv) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = "";
    char *outfile = NULL;
    int snaplen = 65535;
    int promisc = 1;
    int to_ms = 1000;
    int count = 0; // 0 = infinite

    // simple arg parse
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-i") && i+1 < argc) dev = argv[++i];
        else if (!strcmp(argv[i], "-f") && i+1 < argc) filter_exp = argv[++i];
        else if (!strcmp(argv[i], "-w") && i+1 < argc) outfile = argv[++i];
        else if (!strcmp(argv[i], "-c") && i+1 < argc) count = atoi(argv[++i]);
        else {
            printf("Usage: %s -i <iface> [-f <bpf>] [-w <pcap>] [-c <count>]\n", argv[0]);
            return 1;
        }
    }
    if (!dev) {
        printf("Interface required. Use -i\n");
        return 1;
    }

    signal(SIGINT, stop_handler);

    pcap_t *handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    struct bpf_program fp;
    if (filter_exp && strlen(filter_exp) > 0) {
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "pcap_compile failed\n");
            pcap_close(handle);
            return 1;
        }
        pcap_setfilter(handle, &fp);
    }

    if (outfile) {
        dumper = pcap_dump_open(handle, outfile);
        if (!dumper) {
            fprintf(stderr, "pcap_dump_open failed\n");
            pcap_close(handle);
            return 1;
        }
    }

    printf("[+] Capturing on %s BPF='%s' (press Ctrl+C to stop)\n", dev, filter_exp ? filter_exp : "");
    if (count > 0) pcap_loop(handle, count, pkt_handler, NULL);
    else pcap_loop(handle, -1, pkt_handler, NULL);

    if (dumper) pcap_dump_close(dumper);
    pcap_close(handle);
    print_summary();
    return 0;
}
