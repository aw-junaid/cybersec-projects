#!/usr/bin/env python3
"""
subenum.py — Simple Subdomain Enumeration Tool

Usage:
  python3 subenum.py --domain example.com --wordlist common.txt --threads 20

Performs brute-force DNS discovery using socket lookups.
"""
import socket, argparse, concurrent.futures

def check_subdomain(domain, sub):
    subdomain = f"{sub.strip()}.{domain}"
    try:
        ip = socket.gethostbyname(subdomain)
        return (subdomain, ip)
    except socket.gaierror:
        return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--domain", required=True, help="Target domain, e.g. example.com")
    p.add_argument("--wordlist", required=True, help="File with subdomains, one per line")
    p.add_argument("--threads", type=int, default=10)
    args = p.parse_args()

    found = []
    with open(args.wordlist) as f:
        subs = [line.strip() for line in f if line.strip()]

    print(f"[+] Starting subdomain enumeration for {args.domain} with {len(subs)} entries")

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(check_subdomain, args.domain, sub) for sub in subs]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(f"[FOUND] {res[0]} -> {res[1]}")
                found.append(res)

    print(f"\n[+] Total found: {len(found)}")
    with open("subdomains_found.txt", "w") as out:
        for sub, ip in found:
            out.write(f"{sub},{ip}\n")

if __name__ == "__main__":
    main()
