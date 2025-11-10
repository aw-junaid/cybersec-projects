#!/usr/bin/env python3
"""
dir_bruteforce.py — Directory and File Brute-force Discovery Tool

Usage:
  python3 dir_bruteforce.py --url https://example.com --wordlist common.txt --threads 20

Performs automated directory brute-force using HTTP requests.
"""

import argparse, requests, concurrent.futures
from urllib.parse import urljoin

def check_path(base_url, path):
    url = urljoin(base_url, path.strip())
    if not url.endswith("/"):
        url += "/"  # check as directory by default
    try:
        r = requests.get(url, timeout=3, allow_redirects=False)
        code = r.status_code
        if code not in [404, 400]:
            size = len(r.content)
            return (url, code, size)
    except requests.RequestException:
        return None
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="Target base URL (e.g., https://example.com/)")
    p.add_argument("--wordlist", required=True, help="File containing directory names")
    p.add_argument("--threads", type=int, default=10)
    args = p.parse_args()

    print(f"[+] Starting directory brute-force for {args.url}")

    found = []
    with open(args.wordlist) as f:
        dirs = [line.strip() for line in f if line.strip()]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(check_path, args.url, d) for d in dirs]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(f"[FOUND] {res[0]}  (Status: {res[1]}, Size: {res[2]} bytes)")
                found.append(res)

    print(f"\n[+] Found {len(found)} accessible directories/files.")
    with open("dirs_found.txt", "w") as out:
        for url, code, size in found:
            out.write(f"{url} {code} {size}\n")

if __name__ == "__main__":
    main()
