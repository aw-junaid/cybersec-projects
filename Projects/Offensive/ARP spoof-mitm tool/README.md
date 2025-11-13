# Concept: how ARP spoofing / MITM works (high level)

* ARP (Address Resolution Protocol) maps IPv4 addresses to MAC addresses on a local Ethernet segment.
* Hosts keep an ARP cache (IP → MAC). When a host needs a MAC, it broadcasts an ARP request; the owner replies with an ARP reply and the requester records the mapping.
* **ARP spoofing (poisoning)** is when an attacker sends forged ARP replies to one or more hosts, claiming “the gateway’s IP maps to my MAC” (and/or telling the gateway that the victim’s IP maps to the attacker’s MAC). Victim(s) then send Ethernet frames intended for the gateway to the attacker’s NIC.
* The attacker sits in the middle, forwarding (or modifying/dropping) frames between victim and gateway — that’s the MITM. On a switched network this works because ARP is unauthenticated and switches forward based on MAC table entries learned from frames.

---

# Python — scapy-based ARP monitor (recommended, easy to run)

Save as `arp_monitor.py`.

How to run:

* `sudo python3 arp_monitor.py -i eth0` (change `eth0` to your interface)
* Optional: `-w 120` to use a 2-minute window, `-l /tmp/arp.log` to persist logs.

Notes:

* This only *listens* and never sends packets.
* `scapy` must be installed; on some systems install with `pip install scapy` or your distro package manager.
* Run as root since sniffing requires privileges.

---

# C — libpcap-based ARP monitor

Save as `arp_monitor.c`. This is a small, portable pcap program. Compile with `gcc arp_monitor.c -o arp_monitor -lpcap`.


# How to compile and run:

* Install libpcap dev headers on your system (e.g., `sudo apt install libpcap-dev` on Debian/Ubuntu).
* `gcc arp_monitor.c -o arp_monitor -lpcap`
* Run: `sudo ./arp_monitor eth0 300` where `eth0` is the interface and `300` is the time window in seconds.

Notes:

* This C program keeps a tiny in-memory table and prints alerts and info lines to stdout.
* It only inspects ARP packets and does not transmit anything.

---

