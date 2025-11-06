#!/usr/bin/env python3
"""
wifi_tester.py — Educational Wi-Fi Security Analyzer
Safe for home/lab use.

Functions:
- Scan nearby networks using nmcli/iwlist
- Analyze encryption type, SSID patterns, and signal quality
- Flag weak security (Open/WEP)
- Optional dictionary strength test (offline)
"""

import os, re, json, subprocess

def scan_wifi():
    """Use nmcli to scan Wi-Fi networks (Linux)"""
    try:
        # Execute nmcli command to scan for Wi-Fi networks
        # -t: tabular output for easier parsing
        # -f: fields to display (SSID, SECURITY, SIGNAL)
        result = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "device", "wifi", "list"],
            text=True  # Return result as string instead of bytes
        )
    except Exception as e:
        print("Scan failed:", e)
        return []
    
    networks = []
    # Parse each line of the nmcli output
    for line in result.strip().split("\n"):
        if not line.strip(): continue  # Skip empty lines
        
        # Split by colon (nmcli -t format uses colons as separators)
        parts = line.split(":")
        if len(parts) >= 3:
            ssid, sec, signal = parts[0], parts[1] or "OPEN", parts[2]
            networks.append({
                "ssid": ssid or "<hidden>",  # Handle hidden/empty SSIDs
                "security": sec,             # Security type (WPA2, WEP, etc.)
                "signal": int(signal)        # Signal strength percentage
            })
    return networks

def analyze_networks(networks):
    """Analyze network security and assign scores"""
    report = []
    for n in networks:
        score, issues = 100, []  # Start with perfect score
        
        sec = n["security"].upper()
        ssid = n["ssid"]
        
        # Check for weak encryption
        if sec == "OPEN" or "WEP" in sec:
            score -= 70  # Major penalty for weak encryption
            issues.append("Weak encryption (Open/WEP)")
        
        # Check for default/common SSID names
        if re.match(r"(?i)^(linksys|tp-link|netgear|dlink|huawei|tplink)", ssid):
            score -= 15  # Penalty for default SSID
            issues.append("Default SSID detected")
        
        # Check signal strength
        if n["signal"] < 40:
            score -= 10  # Minor penalty for weak signal
            issues.append("Weak signal (may reduce reliability)")
        
        # Add network to report
        report.append({
            "SSID": ssid,
            "Security": sec,
            "Signal": n["signal"],
            "Score": max(score, 0),  # Ensure score doesn't go below 0
            "Issues": issues or ["OK"]  # Default to "OK" if no issues
        })
    return report

def show_report(report):
    """Display the security analysis report"""
    print("\n=== Wi-Fi Security Report ===")
    for r in report:
        print(f"\nSSID: {r['SSID']}")
        print(f"  Security: {r['Security']}")
        print(f"  Signal: {r['Signal']}%")
        print(f"  Score: {r['Score']}/100")
        for issue in r["Issues"]:
            print(f"   - {issue}")

if __name__ == "__main__":
    # Main execution block
    print("Scanning for Wi-Fi networks...")
    nets = scan_wifi()
    
    if not nets:
        print("No networks found or scanning failed.")
        exit()
    
    # Analyze and display results
    report = analyze_networks(nets)
    show_report(report)
    
    # Save results to JSON file
    with open("wifi_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nReport saved to wifi_report.json")
