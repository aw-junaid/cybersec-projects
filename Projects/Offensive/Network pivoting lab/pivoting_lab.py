#!/usr/bin/env python3
import subprocess
import socket
import threading
import time
import paramiko
import socks
import requests
from scapy.all import *
import ipaddress
import json
from dataclasses import dataclass
from typing import List, Dict, Optional
import argparse

@dataclass
class NetworkHost:
    ip: str
    hostname: str
    os: str
    services: Dict[str, int]
    credentials: List[Dict]
    compromised: bool = False

@dataclass
class NetworkSegment:
    name: str
    subnet: str
    hosts: List[NetworkHost]
    gateway: str

class NetworkPivotingLab:
    def __init__(self):
        self.network_segments = []
        self.current_position = None
        self.ssh_tunnels = {}
        self.socks_proxies = {}
        self.setup_lab_environment()
    
    def setup_lab_environment(self):
        """Setup simulated network environment"""
        print("[*] Setting up network pivoting lab environment...")
        
        # DMZ Segment
        dmz_hosts = [
            NetworkHost(
                ip="10.0.1.10",
                hostname="web-server",
                os="Linux Ubuntu 20.04",
                services={"http": 80, "ssh": 22},
                credentials=[{"username": "webadmin", "password": "web123"}]
            ),
            NetworkHost(
                ip="10.0.1.20", 
                hostname="ftp-server",
                os="Windows Server 2019",
                services={"ftp": 21, "rdp": 3389},
                credentials=[{"username": "ftpuser", "password": "ftp123"}]
            )
        ]
        
        dmz_segment = NetworkSegment(
            name="DMZ",
            subnet="10.0.1.0/24",
            hosts=dmz_hosts,
            gateway="10.0.1.1"
        )
        
        # Internal Segment
        internal_hosts = [
            NetworkHost(
                ip="10.0.2.10",
                hostname="db-server",
                os="Linux CentOS 8",
                services={"mysql": 3306, "ssh": 22},
                credentials=[{"username": "dbadmin", "password": "db123"}]
            ),
            NetworkHost(
                ip="10.0.2.20",
                hostname="file-server", 
                os="Windows Server 2019",
                services={"smb": 445, "rdp": 3389},
                credentials=[{"username": "admin", "password": "admin123"}]
            ),
            NetworkHost(
                ip="10.0.2.30",
                hostname="domain-controller",
                os="Windows Server 2022",
                services={"ldap": 389, "kerberos": 88, "dns": 53},
                credentials=[{"username": "Administrator", "password": "DCpass123!"}]
            )
        ]
        
        internal_segment = NetworkSegment(
            name="Internal Network",
            subnet="10.0.2.0/24", 
            hosts=internal_hosts,
            gateway="10.0.2.1"
        )
        
        # Management Segment
        management_hosts = [
            NetworkHost(
                ip="10.0.3.10",
                hostname="admin-workstation",
                os="Windows 10",
                services={"rdp": 3389, "smb": 445},
                credentials=[{"username": "admin", "password": "workstation123"}]
            )
        ]
        
        management_segment = NetworkSegment(
            name="Management Network",
            subnet="10.0.3.0/24",
            hosts=management_hosts,
            gateway="10.0.3.1"
        )
        
        self.network_segments = [dmz_segment, internal_segment, management_segment]
        self.current_position = dmz_hosts[0]  # Start at web server
        
        print("[+] Lab environment configured with 3 network segments")
        print("    - DMZ (10.0.1.0/24)")
        print("    - Internal Network (10.0.2.0/24)") 
        print("    - Management Network (10.0.3.0/24)")
    
    def network_scan(self, target_network: str):
        """Simulate network scanning"""
        print(f"[*] Scanning network: {target_network}")
        
        network = ipaddress.ip_network(target_network)
        alive_hosts = []
        
        # Simulate host discovery
        for host in network.hosts():
            if str(host) in [h.ip for segment in self.network_segments for h in segment.hosts]:
                alive_hosts.append(str(host))
                print(f"    [+] Host found: {host}")
        
        return alive_hosts
    
    def service_enumeration(self, target_ip: str):
        """Enumerate services on target host"""
        print(f"[*] Enumerating services on {target_ip}")
        
        for segment in self.network_segments:
            for host in segment.hosts:
                if host.ip == target_ip:
                    print(f"    [+] Services on {host.hostname}:")
                    for service, port in host.services.items():
                        print(f"        - {service}:{port}")
                    return host.services
        
        return {}
    
    def exploit_service(self, target_ip: str, service: str):
        """Simulate service exploitation"""
        print(f"[*] Attempting to exploit {service} on {target_ip}")
        
        for segment in self.network_segments:
            for host in segment.hosts:
                if host.ip == target_ip and service in host.services:
                    if not host.compromised:
                        host.compromised = True
                        self.current_position = host
                        print(f"[+] Successfully compromised {host.hostname} ({host.ip})")
                        print(f"    OS: {host.os}")
                        print(f"    Credentials: {host.credentials}")
                        return True
                    else:
                        print(f"[-] Host {host.ip} is already compromised")
                        return True
        
        print(f"[-] Failed to exploit {service} on {target_ip}")
        return False
    
    def create_ssh_tunnel(self, jump_host: str, target_host: str, target_port: int, local_port: int):
        """Create SSH tunnel for pivoting"""
        print(f"[*] Creating SSH tunnel through {jump_host} to {target_host}:{target_port}")
        
        # Simulate SSH tunnel creation
        tunnel_id = f"tunnel_{local_port}"
        self.ssh_tunnels[tunnel_id] = {
            'jump_host': jump_host,
            'target_host': target_host,
            'target_port': target_port,
            'local_port': local_port,
            'active': True
        }
        
        print(f"[+] SSH tunnel created: localhost:{local_port} -> {target_host}:{target_port} via {jump_host}")
        return tunnel_id
    
    def setup_socks_proxy(self, pivot_host: str, local_port: int = 1080):
        """Setup SOCKS proxy through pivot host"""
        print(f"[*] Setting up SOCKS proxy through {pivot_host} on port {local_port}")
        
        proxy_id = f"socks_{local_port}"
        self.socks_proxies[proxy_id] = {
            'pivot_host': pivot_host,
            'local_port': local_port,
            'active': True
        }
        
        print(f"[+] SOCKS proxy established on localhost:{local_port} via {pivot_host}")
        return proxy_id
    
    def port_forward(self, pivot_host: str, remote_host: str, remote_port: int, local_port: int):
        """Setup port forwarding through pivot host"""
        print(f"[*] Setting up port forwarding: local:{local_port} -> {remote_host}:{remote_port} via {pivot_host}")
        
        # Simulate port forwarding
        forward_id = f"forward_{local_port}"
        print(f"[+] Port forwarding established: localhost:{local_port} -> {remote_host}:{remote_port}")
        return forward_id
    
    def credential_harvesting(self, target_host: str):
        """Simulate credential harvesting"""
        print(f"[*] Harvesting credentials from {target_host}")
        
        for segment in self.network_segments:
            for host in segment.hosts:
                if host.ip == target_host and host.compromised:
                    credentials = host.credentials
                    print(f"[+] Harvested credentials from {host.hostname}:")
                    for cred in credentials:
                        print(f"    - {cred['username']}:{cred['password']}")
                    return credentials
        
        print(f"[-] No credentials harvested from {target_host}")
        return []
    
    def pass_the_hash(self, target_host: str, username: str, hash_value: str):
        """Simulate pass-the-hash attack"""
        print(f"[*] Attempting pass-the-hash attack on {target_host} with user {username}")
        
        for segment in self.network_segments:
            for host in segment.hosts:
                if host.ip == target_host:
                    # Check if we have access
                    if any(cred['username'] == username for cred in host.credentials):
                        host.compromised = True
                        self.current_position = host
                        print(f"[+] Pass-the-hash successful! Compromised {host.hostname}")
                        return True
        
        print(f"[-] Pass-the-hash attack failed")
        return False
    
    def lateral_movement(self, target_host: str, technique: str = "psexec"):
        """Simulate lateral movement to target host"""
        print(f"[*] Attempting lateral movement to {target_host} using {technique}")
        
        for segment in self.network_segments:
            for host in segment.hosts:
                if host.ip == target_host and not host.compromised:
                    # Check if we have credentials
                    if any(cred for cred in self.current_position.credentials):
                        host.compromised = True
                        old_position = self.current_position
                        self.current_position = host
                        print(f"[+] Lateral movement successful!")
                        print(f"    Moved from {old_position.hostname} to {host.hostname}")
                        return True
        
        print(f"[-] Lateral movement failed")
        return False
    
    def demonstrate_pivoting_scenario(self):
        """Demonstrate complete pivoting scenario"""
        print("\n" + "="*60)
        print("NETWORK PIVOTING SCENARIO DEMONSTRATION")
        print("="*60)
        
        # Step 1: Initial compromise
        print("\n[PHASE 1] Initial Compromise")
        self.exploit_service("10.0.1.10", "http")
        
        # Step 2: Network discovery
        print("\n[PHASE 2] Network Discovery")
        self.network_scan("10.0.2.0/24")
        
        # Step 3: Service enumeration
        print("\n[PHASE 3] Service Enumeration")
        self.service_enumeration("10.0.2.10")
        
        # Step 4: Create pivot
        print("\n[PHASE 4] Pivot Establishment")
        self.create_ssh_tunnel("10.0.1.10", "10.0.2.10", 3306, 3306)
        self.setup_socks_proxy("10.0.1.10", 1080)
        
        # Step 5: Lateral movement
        print("\n[PHASE 5] Lateral Movement")
        self.lateral_movement("10.0.2.20", "psexec")
        
        # Step 6: Credential harvesting
        print("\n[PHASE 6] Credential Harvesting")
        self.credential_harvesting("10.0.2.20")
        
        # Step 7: Domain compromise
        print("\n[PHASE 7] Domain Compromise")
        self.pass_the_hash("10.0.2.30", "Administrator", "aad3b435b51404eeaad3b435b51404ee")
        
        print("\n[+] Pivoting scenario completed successfully!")
    
    def show_network_topology(self):
        """Display current network topology"""
        print("\n" + "="*50)
        print("CURRENT NETWORK TOPOLOGY")
        print("="*50)
        
        for segment in self.network_segments:
            print(f"\n[{segment.name}] - {segment.subnet}")
            for host in segment.hosts:
                status = "COMPROMISED" if host.compromised else "CLEAN"
                current = " <- CURRENT" if host == self.current_position else ""
                print(f"  {host.ip} - {host.hostname} [{status}]{current}")
                for service, port in host.services.items():
                    print(f"      {service}:{port}")

class AdvancedPivotingTechniques:
    """Advanced pivoting techniques implementation"""
    
    @staticmethod
    def dns_tunneling(pivot_host: str, domain: str):
        """Simulate DNS tunneling for data exfiltration"""
        print(f"[*] Setting up DNS tunneling through {pivot_host} using domain {domain}")
        print(f"[+] DNS tunnel established - data can be exfiltrated via DNS queries")
        return True
    
    @staticmethod
    def icmp_tunneling(pivot_host: str):
        """Simulate ICMP tunneling"""
        print(f"[*] Setting up ICMP tunneling through {pivot_host}")
        print(f"[+] ICMP tunnel established - data encapsulated in ICMP packets")
        return True
    
    @staticmethod
    def ssh_dynamic_forwarding(pivot_host: str, local_port: int = 1080):
        """Setup SSH dynamic port forwarding"""
        print(f"[*] Setting up SSH dynamic forwarding through {pivot_host} on port {local_port}")
        print(f"[+] SOCKS proxy available on localhost:{local_port}")
        return True
    
    @staticmethod
    def vpn_pivoting(pivot_host: str, vpn_config: str):
        """Setup VPN pivoting"""
        print(f"[*] Setting up VPN pivot through {pivot_host}")
        print(f"[+] VPN tunnel established - direct access to internal network")
        return True

def main():
    parser = argparse.ArgumentParser(description="Network Pivoting Lab Scripts")
    parser.add_argument("--scenario", action="store_true", help="Run complete pivoting scenario")
    parser.add_argument("--scan", help="Scan specific network")
    parser.add_argument("--exploit", nargs=2, help="Exploit service on target (ip service)")
    parser.add_argument("--tunnel", nargs=4, help="Create SSH tunnel (jump_host target_host target_port local_port)")
    parser.add_argument("--socks", nargs=2, help="Setup SOCKS proxy (pivot_host local_port)")
    parser.add_argument("--lateral", help="Attempt lateral movement to target")
    parser.add_argument("--topology", action="store_true", help="Show network topology")
    
    args = parser.parse_args()
    
    lab = NetworkPivotingLab()
    
    if args.scenario:
        lab.demonstrate_pivoting_scenario()
    
    if args.scan:
        lab.network_scan(args.scan)
    
    if args.exploit:
        lab.exploit_service(args.exploit[0], args.exploit[1])
    
    if args.tunnel:
        lab.create_ssh_tunnel(args.tunnel[0], args.tunnel[1], int(args.tunnel[2]), int(args.tunnel[3]))
    
    if args.socks:
        lab.setup_socks_proxy(args.socks[0], int(args.socks[1]))
    
    if args.lateral:
        lab.lateral_movement(args.lateral)
    
    if args.topology:
        lab.show_network_topology()
    
    if not any(vars(args).values()):
        # Interactive mode
        lab.demonstrate_pivoting_scenario()
        lab.show_network_topology()

if __name__ == "__main__":
    main()
