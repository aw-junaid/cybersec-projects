#!/usr/bin/env python3
"""
packet_crafter.py
Educational packet crafting demo — builds a custom Ethernet/IP/TCP packet
and displays its structure. It does NOT send packets.
"""

import struct
import socket
import binascii

def checksum(data):
    """Compute Internet Checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff

def craft_ip_packet(src_ip, dst_ip, payload=b"HELLO"):
    """Build an IP packet (header + payload)."""
    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    tos = 0
    total_length = 20 + len(payload)
    identification = 54321
    flags_fragment = 0
    ttl = 64
    protocol = socket.IPPROTO_TCP
    header_checksum = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, tos, total_length, identification,
                            flags_fragment, ttl, protocol, header_checksum,
                            src_addr, dst_addr)
    header_checksum = checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s",
                            ver_ihl, tos, total_length, identification,
                            flags_fragment, ttl, protocol, header_checksum,
                            src_addr, dst_addr)
    return ip_header + payload

def main():
    src_ip = "192.168.0.10"
    dst_ip = "192.168.0.20"
    payload = b"Educational packet crafting demo"
    packet = craft_ip_packet(src_ip, dst_ip, payload)
    print(f"Packet from {src_ip} to {dst_ip}")
    print(f"Length: {len(packet)} bytes")
    print("Hex dump:")
    print(binascii.hexlify(packet).decode())

if __name__ == "__main__":
    main()
