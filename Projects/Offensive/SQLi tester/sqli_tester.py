#!/usr/bin/env python3
"""
sqli_tester.py - Safe, lab-only SQLi detection tool (Python)

Usage:
  python3 sqli_tester.py --url "http://127.0.0.1:8000/search?q=test"

Notes:
- ONLY test targets you own or are authorized to test.
- This tool performs non-destructive checks (boolean & error-based) and reports potential findings.
"""
import argparse
import hashlib
import json
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

# conservative payloads for detection only
PAYLOADS = {
    "error_quote": "'",                             # quick error-based probe (single quote)
    "bool_true": "' OR '1'='1",                     # boolean true
    "bool_false": "' OR '1'='2",                    # boolean false (control)
}

TIMEOUT = 8  # seconds

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def send_request(url, method='GET', data=None, headers=None):
    try:
        if method.upper() == 'GET':
            r = requests.get(url, timeout=TIMEOUT, headers=headers, allow_redirects=True)
        else:
            r = requests.post(url, data=data, timeout=TIMEOUT, headers=headers, allow_redirects=True)
        return r.status_code, len(r.content), sha256_bytes(r.content), r.text
    except requests.RequestException as e:
        return None, None, None, f"request_error: {e}"

def build_url_with_param(url, param, value):
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    new_q = urlencode(qs, doseq=True)
    return urlunparse(p._replace(query=new_q))

def analyze_param(url, param):
    findings = []
    # baseline using a benign marker
    baseline_url = build_url_with_param(url, param, "SAFE_TEST_12345")
    base_status, base_len, base_hash, base_text = send_request(baseline_url)
    if base_status is None:
        return {"param": param, "error": "baseline_request_failed", "detail": base_text}

    # Error-based probe
    probe_url = build_url_with_param(url, param, PAYLOADS["error_quote"])
    p_status, p_len, p_hash, p_text = send_request(probe_url)
    evidence = []
    if p_status is None:
        evidence.append({"type":"request_error","payload":PAYLOADS["error_quote"], "detail": p_text})
    else:
        # look for common SQL error strings (simple heuristics)
        sql_errors = ["sql syntax", "mysql", "syntax error", "unterminated quoted string",
                      "sqlite error", "odbc", "psql", "pg_query"]
        lower = p_text.lower()
        for sig in sql_errors:
            if sig in lower:
                evidence.append({"type":"sql_error_string", "payload":PAYLOADS["error_quote"], "match": sig})
                break

    # Boolean-based check: compare true vs false payloads
    true_url = build_url_with_param(url, param, PAYLOADS["bool_true"])
    false_url = build_url_with_param(url, param, PAYLOADS["bool_false"])
    t_status, t_len, t_hash, t_text = send_request(true_url)
    f_status, f_len, f_hash, f_text = send_request(false_url)

    # If true/false responses differ strongly while baseline equals one of them -> likely injectable
    bool_evidence = {}
    if None not in (t_status, f_status):
        bool_evidence['true']  = {"status": t_status, "length": t_len, "hash": t_hash}
        bool_evidence['false'] = {"status": f_status, "length": f_len, "hash": f_hash}
        # Compare hashes / lengths
        if t_hash != f_hash:
            # also check whether baseline matches false case (common pattern)
            baseline_matches_false = (base_hash == f_hash)
            baseline_matches_true = (base_hash == t_hash)
            bool_evidence['conclusion'] = "diff"
            bool_evidence['baseline_matches_false'] = baseline_matches_false
            bool_evidence['baseline_matches_true'] = baseline_matches_true
            evidence.append({"type":"boolean_difference", "detail": bool_evidence})
    else:
        evidence.append({"type":"bool_request_error", "true_status": t_status, "false_status": f_status})

    return {"param": param, "baseline": {"status":base_status,"len":base_len,"hash":base_hash},
            "evidence": evidence}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Target URL containing parameter(s) to test. Example: http://127.0.0.1:8000/search?q=test")
    parser.add_argument("--out", default="sqli_report.json")
    parser.add_argument("--method", choices=['GET','POST'], default='GET')
    args = parser.parse_args()

    url = args.url
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    if not params:
        print("[!] No parameters found in URL. Provide a URL with at least one query parameter.")
        sys.exit(1)

    report = {"target": url, "results": [], "note": "Lab-only, non-destructive checks (boolean & error-based)"}
    for param in params:
        print(f"[+] Testing parameter: {param}")
        res = analyze_param(url, param)
        report['results'].append(res)

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Done. Report saved to {args.out}")

if __name__ == "__main__":
    main()
