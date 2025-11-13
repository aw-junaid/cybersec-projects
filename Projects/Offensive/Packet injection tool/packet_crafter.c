/*
 * packet_crafter.c
 * Educational example — builds an IPv4 packet in memory and prints its bytes.
 * Does not send anything.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

unsigned short checksum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    unsigned char packet[1024];
    memset(packet, 0, sizeof(packet));

    // Build minimal IPv4 header
    struct iphdr {
        unsigned char  ihl:4, version:4;
        unsigned char  tos;
        unsigned short tot_len;
        unsigned short id;
        unsigned short frag_off;
        unsigned char  ttl;
        unsigned char  protocol;
        unsigned short check;
        unsigned int   saddr;
        unsigned int   daddr;
    };

    struct iphdr *ip = (struct iphdr *)packet;

    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    const char *payload = "Educational packet crafting demo";
    int payload_len = strlen(payload);
    ip->tot_len = htons(sizeof(struct iphdr) + payload_len);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 6; // TCP
    ip->saddr = inet_addr("192.168.0.10");
    ip->daddr = inet_addr("192.168.0.20");
    ip->check = 0;
    ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr)/2);

    memcpy(packet + sizeof(struct iphdr), payload, payload_len);

    int packet_len = sizeof(struct iphdr) + payload_len;
    printf("Packet length: %d bytes\n", packet_len);
    printf("Hex dump:\n");
    for (int i = 0; i < packet_len; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\nDone.\n");

    return 0;
}
