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
        result = subprocess.check_output(
            ["nmcli", "-t", "-f", "SSID,SECURITY,SIGNAL", "device", "wifi", "list"],
            text=True
        )
    except Exception as e:
        print("Scan failed:", e)
        return []
    networks = []
    for line in result.strip().split("\n"):
        if not line.strip(): continue
        parts = line.split(":")
        if len(parts) >= 3:
            ssid, sec, signal = parts[0], parts[1] or "OPEN", parts[2]
            networks.append({
                "ssid": ssid or "<hidden>",
                "security": sec,
                "signal": int(signal)
            })
    return networks

def analyze_networks(networks):
    report = []
    for n in networks:
        score, issues = 100, []
        sec = n["security"].upper()
        ssid = n["ssid"]
        if sec == "OPEN" or "WEP" in sec:
            score -= 70
            issues.append("Weak encryption (Open/WEP)")
        if re.match(r"(?i)^(linksys|tp-link|netgear|dlink|huawei|tplink)", ssid):
            score -= 15
            issues.append("Default SSID detected")
        if n["signal"] < 40:
            score -= 10
            issues.append("Weak signal (may reduce reliability)")
        report.append({
            "SSID": ssid,
            "Security": sec,
            "Signal": n["signal"],
            "Score": max(score, 0),
            "Issues": issues or ["OK"]
        })
    return report

def show_report(report):
    print("\n=== Wi-Fi Security Report ===")
    for r in report:
        print(f"\nSSID: {r['SSID']}")
        print(f"  Security: {r['Security']}")
        print(f"  Signal: {r['Signal']}%")
        print(f"  Score: {r['Score']}/100")
        for issue in r["Issues"]:
            print(f"   - {issue}")

if __name__ == "__main__":
    nets = scan_wifi()
    if not nets:
        print("No networks found or scanning failed.")
        exit()
    report = analyze_networks(nets)
    show_report(report)
    with open("wifi_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("\nReport saved to wifi_report.json")
