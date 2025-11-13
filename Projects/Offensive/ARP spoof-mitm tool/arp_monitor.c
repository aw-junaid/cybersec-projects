/*
 * arp_monitor.c - defensive ARP observer using libpcap
 *
 * Compile:
 *   gcc arp_monitor.c -o arp_monitor -lpcap
 *
 * Run:
 *   sudo ./arp_monitor <interface> [window_seconds]
 *
 * What it does:
 *   - Captures ARP packets on the given interface.
 *   - Maintains a short-lived mapping table IP -> last-seen MACs (within window).
 *   - Prints alert when a single IP is seen with different MAC addresses within the time window.
 *
 * Note: Only listens (read-only). Use in isolated lab or networks you own.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define DEFAULT_WINDOW 300  /* seconds */

typedef struct mac_entry {
    unsigned char mac[6];
    time_t ts;
    struct mac_entry *next;
} mac_entry_t;

typedef struct ip_record {
    uint32_t ip;            /* network byte order */
    mac_entry_t *macs;      /* linked list of mac entries (recent) */
    struct ip_record *next;
} ip_record_t;

static ip_record_t *records = NULL;
static int window_seconds = DEFAULT_WINDOW;

static void print_mac(unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static mac_entry_t *find_mac(mac_entry_t *head, unsigned char *mac) {
    mac_entry_t *p = head;
    while (p) {
        if (memcmp(p->mac, mac, 6) == 0) return p;
        p = p->next;
    }
    return NULL;
}

static void add_or_update_record(uint32_t ip, unsigned char *mac) {
    time_t now = time(NULL);
    ip_record_t *r = records;
    while (r) {
        if (r->ip == ip) break;
        r = r->next;
    }
    if (!r) {
        r = calloc(1, sizeof(ip_record_t));
        r->ip = ip;
        r->macs = NULL;
        r->next = records;
        records = r;
    }

    /* Cleanup old mac entries */
    mac_entry_t **pp = &r->macs;
    while (*pp) {
        if (difftime(now, (*pp)->ts) > window_seconds) {
            mac_entry_t *old = *pp;
            *pp = old->next;
            free(old);
        } else {
            pp = &(*pp)->next;
        }
    }

    /* If MAC already present, update ts; else add new mac entry */
    mac_entry_t *m = find_mac(r->macs, mac);
    if (m) {
        m->ts = now;
    } else {
        mac_entry_t *newm = calloc(1, sizeof(mac_entry_t));
        memcpy(newm->mac, mac, 6);
        newm->ts = now;
        newm->next = r->macs;
        r->macs = newm;
    }

    /* Count distinct MACs now */
    int count = 0;
    mac_entry_t *iter = r->macs;
    while (iter) {
        count++;
        iter = iter->next;
    }
    char ipbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
    if (count > 1) {
        printf("[ALERT] IP %s has %d distinct MACs within %d seconds: ",
               ipbuf, count, window_seconds);
        iter = r->macs;
        while (iter) {
            print_mac(iter->mac);
            printf(" ");
            iter = iter->next;
        }
        printf("\n");
    } else {
        printf("[INFO] IP %s -> ", ipbuf);
        print_mac(mac);
        printf("\n");
    }
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    /* Expect Ethernet header + ARP */
    if (h->caplen < sizeof(struct ether_header) + sizeof(struct ether_arp)) return;

    const struct ether_header *eth = (struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

    const struct ether_arp *arp = (struct ether_arp *)(bytes + sizeof(struct ether_header));
    uint16_t op = ntohs(arp->ea_hdr.ar_op);
    /* op 1 = request, 2 = reply */
    (void)op; /* we don't need to distinguish, but could */
    unsigned char *sha = (unsigned char *)arp->arp_sha;
    unsigned char *spa = (unsigned char *)arp->arp_spa;

    uint32_t ip;
    memcpy(&ip, spa, 4);

    add_or_update_record(ip, sha);
}

int main(int argc, char **argv) {
    char *dev = NULL;
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [window_seconds]\n", argv[0]);
        return 1;
    }
    dev = argv[1];
    if (argc >= 3) window_seconds = atoi(argv[2]);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    /* We only want ARP packets */
    if (pcap_compile(handle, NULL, "arp", 1, PCAP_NETMASK_UNKNOWN) < 0) {
        /* ignore compile error, set filter via pcap_setfilter if desired */
    }
    printf("Listening on %s (window=%d seconds). Ctrl-C to stop.\n", dev, window_seconds);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
