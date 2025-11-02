#!/usr/bin/env python3
"""
sniffer.py - Simple Packet Sniffer & Network Analyzer using Scapy

A comprehensive network packet sniffer that captures, analyzes, and displays
network traffic with real-time statistics and protocol analysis.

Features:
- Live packet capture from any network interface
- BPF (Berkeley Packet Filter) filtering support (tcpdump syntax)
- Protocol analysis and statistics (TCP, UDP, ICMP, IPv6)
- Top talkers identification
- PCAP file saving for later analysis
- Real-time capture statistics

Dependencies: scapy
Install: sudo apt update && sudo apt install -y python3-scapy
          OR pip install scapy

Usage Examples:
1. Capture all HTTP traffic on eth0:
   sudo python3 sniffer.py --iface eth0 --bpf "tcp port 80"

2. Capture 100 IP packets on wireless interface:
   sudo python3 sniffer.py --iface wlan0 --bpf "ip" --count 100

3. Capture all traffic and save to file:
   sudo python3 sniffer.py --iface eth0 --save capture.pcap

4. Show top 5 talkers from capture:
   sudo python3 sniffer.py --iface eth0 --top 5

Note: Requires root privileges for raw packet capture
"""

import argparse
import sys
import time
from collections import Counter, defaultdict, deque
from scapy.all import sniff, PcapWriter, IP, IPv6, TCP, UDP, ICMP


def parse_args():
    """
    Parse command line arguments for the sniffer
    
    Returns:
        argparse.Namespace: Parsed command line arguments
    """
    parser = argparse.ArgumentParser(
        description="Simple packet sniffer and network analyzer using Scapy",
        epilog="Example: sudo python3 sniffer.py --iface eth0 --bpf 'tcp port 80' --count 100"
    )
    
    # Required interface argument
    parser.add_argument(
        "--iface", 
        required=True,
        help="Network interface to capture on (e.g., eth0, wlan0, lo)"
    )
    
    # Optional BPF filter
    parser.add_argument(
        "--bpf", 
        default="",
        help="BPF filter string in tcpdump syntax (e.g., 'tcp and port 80', 'udp', 'icmp')"
    )
    
    # Packet count limit
    parser.add_argument(
        "--count", 
        type=int, 
        default=0,
        help="Number of packets to capture (0 = unlimited, Ctrl+C to stop)"
    )
    
    # Save to PCAP file
    parser.add_argument(
        "--save", 
        default=None,
        help="Save captured packets to PCAP file for later analysis"
    )
    
    # Top talkers display
    parser.add_argument(
        "--top", 
        type=int, 
        default=10,
        help="Number of top talkers to display in statistics"
    )
    
    return parser.parse_args()


class Analyzer:
    """
    Packet analyzer class that processes captured packets and maintains statistics
    
    Attributes:
        pkts (int): Total packets captured
        bytes (int): Total bytes captured
        proto (Counter): Protocol frequency counter
        talkers (Counter): IP address frequency counter
        start (float): Capture start time
        top_n (int): Number of top talkers to display
        pcap (PcapWriter): PCAP file writer object
        recent (deque): Recent packets buffer for real-time display
    """
    
    def __init__(self, save=None, top_n=10):
        """
        Initialize the packet analyzer
        
        Args:
            save (str, optional): PCAP filename to save captures
            top_n (int, optional): Number of top talkers to display
        """
        # Basic statistics
        self.pkts = 0
        self.bytes = 0
        self.proto = Counter()  # Protocol counter: TCP, UDP, ICMP, etc.
        self.talkers = Counter()  # IP address counter for top talkers
        
        # Timing and configuration
        self.start = time.time()
        self.top_n = top_n
        
        # PCAP file output
        self.pcap = PcapWriter(save, append=True, sync=True) if save else None
        
        # Recent packets buffer (last 20 packets)
        self.recent = deque(maxlen=20)

    def process(self, pkt):
        """
        Process each captured packet and update statistics
        
        Args:
            pkt (scapy.packet.Packet): Captured packet to process
        """
        # Update packet and byte counters
        self.pkts += 1
        rawlen = len(pkt)
        self.bytes += rawlen
        
        # Store recent packet for potential real-time analysis
        self.recent.append((time.time(), pkt))

        # Save packet to PCAP file if enabled
        if self.pcap:
            try:
                self.pcap.write(pkt)
            except Exception as e:
                # Silently handle write errors to avoid disrupting capture
                pass

        # Protocol analysis - IPv4 packets
        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = ip.proto
            
            # Count protocols by IP protocol number
            if proto == 6:  # TCP
                self.proto['TCP'] += 1
            elif proto == 17:  # UDP
                self.proto['UDP'] += 1
            elif proto == 1:  # ICMP
                self.proto['ICMP'] += 1
            else:  # Other IP protocols
                self.proto['IP-OTHER'] += 1
            
            # Update talker statistics
            self.talkers[src] += 1  # Source sent a packet
            self.talkers[dst] += 0  # Ensure destination is in counter
            
        # IPv6 packet analysis
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            self.proto['IPv6'] += 1
            self.talkers[ip6.src] += 1
            self.talkers[ip6.dst] += 0
            
        # Non-IP packets (ARP, etc.)
        else:
            self.proto['OTHER'] += 1

        # Display progress every 50 packets
        if self.pkts % 50 == 0:
            self.print_summary(inline=True)

    def print_summary(self, inline=False):
        """
        Print capture statistics summary
        
        Args:
            inline (bool): If True, print inline update; if False, print full report
        """
        elapsed = max(1.0, time.time() - self.start)
        pps = self.pkts / elapsed  # Packets per second
        bps = self.bytes / elapsed  # Bytes per second
        
        if inline:
            # Real-time inline display
            sys.stdout.write(
                f"\rPkts:{self.pkts}  Bytes:{self.bytes}  "
                f"PPS:{pps:.1f}  BPS:{bps:.1f}  TopTalkers:{self.top_n} "
            )
            sys.stdout.flush()
        else:
            # Final detailed report
            print("\n" + "="*25 + " Capture Summary " + "="*25)
            print(f"Duration: {elapsed:.1f}s  Packets: {self.pkts}  Bytes: {self.bytes}")
            print(f"Average Rate: {pps:.1f} packets/sec, {bps:.1f} bytes/sec")
            print("\nProtocol Distribution:")
            for proto, count in self.proto.most_common():
                print(f"  {proto:10} : {count:6} packets")
            
            print(f"\nTop {self.top_n} Talkers:")
            for ip, cnt in self.talkers.most_common(self.top_n):
                print(f"  {ip:15} : {cnt:6} packets")
            print("="*67)

    def close(self):
        """Clean up resources, close PCAP file if open"""
        if self.pcap:
            try:
                self.pcap.close()
            except Exception:
                pass


def main():
    """
    Main function - orchestrates packet capture and analysis
    """
    # Parse command line arguments
    args = parse_args()
    
    # Initialize analyzer with user options
    analyzer = Analyzer(save=args.save, top_n=args.top)
    
    print(f"[+] Starting packet capture on interface: {args.iface}")
    if args.bpf:
        print(f"[+] BPF Filter: '{args.bpf}'")
    if args.save:
        print(f"[+] Saving packets to: {args.save}")
    if args.count > 0:
        print(f"[+] Capture limit: {args.count} packets")
    else:
        print("[+] Capture: Unlimited (Press Ctrl+C to stop)")
    print("[+] Analyzing packets...")
    
    try:
        # Start packet capture using Scapy's sniff function
        sniff(
            iface=args.iface,      # Network interface
            filter=args.bpf or None,  # BPF filter (None = all traffic)
            prn=analyzer.process,  # Callback for each packet
            store=False,           # Don't store packets in memory
            count=args.count       # Packet count limit
        )
        
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        print("\n[!] Capture interrupted by user")
    except PermissionError:
        # Common error - need root privileges
        print("[!] Permission error: Raw packet capture requires root privileges")
        print("[!] Please run with: sudo python3 sniffer.py [options]")
        sys.exit(1)
    except Exception as e:
        # Handle other unexpected errors
        print(f"[!] Capture error: {e}")
        sys.exit(1)
    finally:
        # Always print final summary and clean up
        analyzer.print_summary()
        analyzer.close()


if __name__ == "__main__":
    main()
