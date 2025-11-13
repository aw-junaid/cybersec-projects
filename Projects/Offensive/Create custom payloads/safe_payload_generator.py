#!/usr/bin/env python3
"""
safe_payload_generator.py

Purpose:
  - Modular, benign payload generator for testing and IDS/WAF/ parser robustness.
  - Produces template, fuzz, pattern, and protocol-mock payloads.
  - NEVER produces exploit code or executable shellcode.
  - Outputs payload files and a JSON manifest with metadata.

Requirements:
  - Python 3.8+
  - Only uses stdlib

Usage examples:
  python3 safe_payload_generator.py --module fuzz --count 10 --size 512 --outdir ./out
  python3 safe_payload_generator.py --module template --template http --count 3 --outdir ./out
  python3 safe_payload_generator.py --module pattern --pattern inc --size 1024 --outdir ./out --encode base64
"""

import argparse
import os
import json
import time
import base64
import gzip
import hashlib
import random
import string
from typing import Callable

# --- Utility functions ----------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

# --- Payload modules (each returns bytes) ---------------------------------

def module_template_http(params) -> bytes:
    """
    Build a harmless HTTP-like request as bytes (no exploit payloads).
    Useful for parser testing.
    """
    method = params.get("method", "GET")
    path = params.get("path", "/test/resource")
    host = params.get("host", "example.local")
    user_agent = params.get("ua", "PayloadGen/1.0")
    body = params.get("body", "")
    headers = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Connection: close",
    ]
    if body:
        headers.append(f"Content-Length: {len(body)}")
    text = "\r\n".join(headers) + "\r\n\r\n" + body
    return text.encode("utf-8")

def module_template_json(params) -> bytes:
    obj = params.get("obj", {"msg": "test", "id": 1})
    pretty = params.get("pretty", False)
    if pretty:
        s = json.dumps(obj, indent=2)
    else:
        s = json.dumps(obj, separators=(",", ":"))
    return s.encode("utf-8")

def module_fuzz_random(params) -> bytes:
    """Random bytes fuzz payload (non-zero constrained to printable by default)."""
    size = int(params.get("size", 256))
    printable = params.get("printable", True)
    rng = random.Random(params.get("seed", None))
    if printable:
        choices = string.printable
        return "".join(rng.choice(choices) for _ in range(size)).encode("utf-8", errors="ignore")
    else:
        return bytes(rng.getrandbits(8) for _ in range(size))

def module_pattern(params) -> bytes:
    """
    Patterns:
      - zeros : all 0x00
      - ff    : all 0xFF
      - inc   : 0x00,0x01,0x02... wrapping
      - repeat: repeats a short token
    """
    size = int(params.get("size", 256))
    ptype = params.get("pattern", "zeros")
    if ptype == "zeros":
        return bytes([0] * size)
    if ptype == "ff":
        return bytes([0xFF] * size)
    if ptype == "inc":
        return bytes((i & 0xFF) for i in range(size))
    if ptype == "repeat":
        token = params.get("token", "TEST")
        b = token.encode("utf-8")
        out = bytearray()
        while len(out) < size:
            out.extend(b)
        return bytes(out[:size])
    # default
    return bytes([0] * size)

def module_protocol_mock_dns(params) -> bytes:
    """
    Very small, benign DNS-like UDP payload *structure* for parser testing.
    Not a real packet — just the DNS bytes for use in feeding parsers or creating pcaps.
    """
    # Build a fake DNS header + a question for example.com
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = tid.to_bytes(2, "big") + flags.to_bytes(2, "big") + \
             qdcount.to_bytes(2, "big") + ancount.to_bytes(2, "big") + \
             nscount.to_bytes(2, "big") + arcount.to_bytes(2, "big")
    # question name 'example.com'
    qname = b""
    for part in ("example","com"):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b'\x00'
    qtype = (1).to_bytes(2,"big")   # A
    qclass = (1).to_bytes(2,"big")  # IN
    return header + qname + qtype + qclass

# Registry
MODULES = {
    "http": module_template_http,
    "json": module_template_json,
    "fuzz": module_fuzz_random,
    "pattern": module_pattern,
    "dns-mock": module_protocol_mock_dns,
}

# --- Encoding / postprocessing -------------------------------------------

def apply_encoding(data: bytes, encode: str) -> bytes:
    if not encode:
        return data
    if encode == "hex":
        return base64.b16encode(data)  # uppercase hex
    if encode == "base64":
        return base64.b64encode(data)
    if encode == "gzip":
        return gzip.compress(data)
    raise ValueError(f"Unknown encode: {encode}")

# --- Main generator ------------------------------------------------------

def generate_payloads(modname: str, params: dict, count: int, outdir: str, encode: str):
    if modname not in MODULES:
        raise ValueError(f"Unknown module {modname}. Available: {list(MODULES.keys())}")
    func: Callable = MODULES[modname]
    ensure_dir(outdir)
    manifest = []
    for i in range(count):
        # allow per-instance seed variation
        p = dict(params)
        if "seed" in p and p["seed"] is None:
            p["seed"] = int(time.time() * 1000) ^ i
        elif "seed" in p:
            # if seed is numeric string, convert
            try:
                p["seed"] = int(p["seed"])
            except Exception:
                pass

        data = func(p)
        out = apply_encoding(data, encode)
        # create filename
        safe_mod = modname.replace("/", "_")
        ext = "bin"
        if encode == "hex":
            ext = "hex"
        elif encode == "base64":
            ext = "b64"
        elif encode == "gzip":
            ext = "gz"
        name = f"{safe_mod}_{i+1}.{ext}"
        path = os.path.join(outdir, name)
        write_file(path, out)
        meta = {
            "filename": name,
            "module": modname,
            "params": p,
            "size_raw": len(data),
            "size_out": len(out),
            "sha256": sha256_hex(out),
            "timestamp": time.time()
        }
        manifest.append(meta)
        print(f"[+]: wrote {path}  raw={meta['size_raw']} out={meta['size_out']} sha256={meta['sha256']}")
    # write manifest
    manifest_path = os.path.join(outdir, "manifest.json")
    with open(manifest_path, "w") as mf:
        json.dump(manifest, mf, indent=2)
    print(f"[+]: manifest at {manifest_path}")
    return manifest

# --- CLI -----------------------------------------------------------------

def parse_kv_list(kvs):
    """parse list of key=val to dict"""
    out = {}
    for kv in kvs or []:
        if "=" in kv:
            k, v = kv.split("=", 1)
            out[k] = try_parse_number(v)
    return out

def try_parse_number(s):
    # try int, float, else keep string or boolean-like
    if s.lower() in ("true","false"):
        return s.lower() == "true"
    try:
        return int(s)
    except:
        try:
            return float(s)
        except:
            return s

def main():
    p = argparse.ArgumentParser(description="Safe modular payload generator (benign test payloads only).")
    p.add_argument("--module", "-m", required=True, help=f"module name {list(MODULES.keys())}")
    p.add_argument("--count", "-c", type=int, default=1)
    p.add_argument("--outdir", "-o", default="./payloads")
    p.add_argument("--encode", choices=["hex","base64","gzip","none"], default="none")
    p.add_argument("--param", "-P", action="append", help="module parameter key=val (can repeat)", default=[])
    args = p.parse_args()

    params = parse_kv_list(args.param)
    enc = None if args.encode == "none" else args.encode
    generate_payloads(args.module, params, args.count, args.outdir, enc)

if __name__ == "__main__":
    main()
