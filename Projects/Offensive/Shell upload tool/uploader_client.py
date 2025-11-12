#!/usr/bin/env python3
"""
uploader_client.py - Safe uploader client
Usage: python3 uploader_client.py --host 127.0.0.1 --port 8000 --token mylabtoken file_to_upload
"""
import argparse, requests, os, sys, pathlib

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--token", required=True)
    p.add_argument("file", help="local file to upload")
    args = p.parse_args()

    if not os.path.isfile(args.file):
        print("File not found:", args.file); sys.exit(1)

    url = f"http://{args.host}:{args.port}/upload"
    with open(args.file, "rb") as fh:
        files = {"file": (pathlib.Path(args.file).name, fh)}
        headers = {"X-UPLOAD-TOKEN": args.token}
        r = requests.post(url, files=files, headers=headers, timeout=20)
    try:
        print("Server response:", r.status_code, r.json())
    except Exception:
        print("Server response (raw):", r.status_code, r.text)

if __name__ == "__main__":
    main()
