#!/usr/bin/env python3
"""
csrf_checker.py
Usage: python3 csrf_checker.py <url>
Example: python3 csrf_checker.py https://example.com/login
Notes: Safe, read-only scanner. Does not submit forms or perform harmful actions.
Dependencies: pip install requests beautifulsoup4
"""
import sys
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

COMMON_CSRF_NAMES = {
    "csrf", "csrf_token", "csrf-token", "authenticity_token",
    "_csrf", "__requestverificationtoken", "token", "xsrf-token", "anti_csrf"
}
STATE_GET_KEYWORDS = ("delete", "remove", "logout", "signout", "transfer", "withdraw", "confirm")

def fetch(url):
    try:
        r = requests.get(url, timeout=10)
        return r
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return None

def cookie_checks(response):
    cookies = []
    raw = response.headers.get("Set-Cookie")
    if not raw:
        return cookies
    # requests exposes cookie attributes partially; parse header for attributes
    for header in response.headers.get_all("Set-Cookie") if hasattr(response.headers, "get_all") else [raw]:
        cookies.append(header)
    return cookies

def has_csrf_token(inputs):
    for inp in inputs:
        name = (inp.get("name") or "").lower()
        _id = (inp.get("id") or "").lower()
        typ = (inp.get("type") or "").lower()
        # hidden inputs with common csrf-like names
        if typ == "hidden" and (name in COMMON_CSRF_NAMES or _id in COMMON_CSRF_NAMES):
            return True, name or _id
        # some tokens are not hidden but named explicitly
        if name in COMMON_CSRF_NAMES or _id in COMMON_CSRF_NAMES:
            return True, name or _id
    return False, None

def analyze_forms(soup, base_url):
    findings = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        action = urljoin(base_url, action)
        method = (form.get("method") or "get").lower()
        inputs = form.find_all("input")
        token_found, token_name = has_csrf_token(inputs)
        # Heuristic: consider forms with POST and no token as risky
        risk = None
        if method == "post" and not token_found:
            risk = "POST form without detectable CSRF token"
        # mark state-changing GET forms/links
        if method == "get":
            for kw in STATE_GET_KEYWORDS:
                if kw in action.lower():
                    if risk:
                        risk += f"; GET action contains '{kw}'"
                    else:
                        risk = f"GET action contains state keyword '{kw}'"
        findings.append({
            "action": action,
            "method": method,
            "inputs_count": len(inputs),
            "token_found": token_found,
            "token_name": token_name,
            "risk": risk
        })
    return findings

def analyze_links(soup, base_url):
    findings = []
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a['href'])
        for kw in STATE_GET_KEYWORDS:
            if kw in href.lower():
                findings.append({"url": href, "keyword": kw})
                break
    return findings

def report(url):
    print(f"Scanning (read-only): {url}\n")
    resp = fetch(url)
    if resp is None:
        return
    print(f"HTTP {resp.status_code} {resp.reason}")
    # cookies
    raw_cookies = cookie_checks(resp)
    if raw_cookies:
        print("\nSet-Cookie headers found:")
        for c in raw_cookies:
            print("  " + c)
            if "samesite" not in c.lower():
                print("    -> Missing SameSite attribute (recommend 'Lax' or 'Strict').")
    else:
        print("\nNo Set-Cookie header found on initial GET.")

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = analyze_forms(soup, url)
    if forms:
        print(f"\nFound {len(forms)} form(s):")
        for i, f in enumerate(forms, 1):
            print(f" {i}. action={f['action']} method={f['method'].upper()} inputs={f['inputs_count']}")
            if f['token_found']:
                print(f"    - CSRF token detected (field: {f['token_name']})")
            else:
                print("    - NO detectable CSRF token.")
            if f['risk']:
                print(f"    - RISK: {f['risk']}")
    else:
        print("\nNo forms detected on the page.")

    links = analyze_links(soup, url)
    if links:
        print(f"\nPotential state-changing GET links ({len(links)}):")
        for l in links:
            print(f"  - {l['url']} (contains '{l['keyword']}')")
    else:
        print("\nNo obvious state-changing GET links detected heuristically.")

    print("\nRecommendations:")
    print(" - Add per-request anti-CSRF tokens to forms and verify server-side.")
    print(" - Use SameSite=Lax or Strict on session cookies where practical.")
    print(" - Avoid performing state changes via GET requests.")
    print(" - Verify Referer/Origin server-side as an additional check for sensitive endpoints.")
    print("\nNote: this is a heuristic, read-only tool. False positives/negatives are possible.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 csrf_checker.py <url>")
        sys.exit(1)
    target = sys.argv[1]
    report(target)
