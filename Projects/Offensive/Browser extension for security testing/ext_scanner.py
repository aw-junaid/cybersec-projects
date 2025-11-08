#!/usr/bin/env python3
"""
ext_scanner.py - Browser-like page scanner using Selenium

Usage:
  python3 ext_scanner.py --url https://example.local --out report.json [--active]

Notes:
- Passive by default. --active enables safe non-executing marker injection (lab-only).
- Only target sites you own or have permission to test.
"""
import argparse, json, time, uuid
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FxOptions

# ---------- Config ----------
WAIT_SECONDS = 1.0
# ----------------------------

def collect_passive(driver, url):
    """Run JS in page to collect headers and DOM info (passive)."""
    info = {"url": url, "timestamp": time.time(), "csp": None, "meta": [], "scripts": [], "forms": [], "inline_scripts": 0}
    # read document properties
    js = """
    (function(){
      try {
        let out = {};
        out.title = document.title;
        out.location = location.href;
        out.meta = Array.from(document.getElementsByTagName('meta')).map(m => ({name: m.name || m.getAttribute('property'), content: m.content}));
        out.scripts = Array.from(document.getElementsByTagName('script')).map(s => ({src: s.src||null, inline: !!(s.src==''||!s.src)}));
        out.forms = Array.from(document.getElementsByTagName('form')).map(f => ({action: f.getAttribute('action'), method: (f.getAttribute('method')||'GET').toUpperCase(), inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i=>({name:i.name||null,type:i.type||i.tagName}))}));
        out.csp = null;
        // try reading meta CSP if present
        const meta = Array.from(document.querySelectorAll('meta[http-equiv]')).find(m=>/content-security-policy/i.test(m.httpEquiv));
        if (meta) out.csp = meta.content;
        return out;
      } catch(e) { return {error: String(e)}; }
    })();
    """
    result = driver.execute_script(js)
    info.update(result if isinstance(result, dict) else {})
    # count inline scripts
    info["inline_scripts"] = sum(1 for s in (info.get("scripts") or []) if s.get("inline"))
    return info

def safe_active_test_reflection(driver, marker):
    """
    Safe active check: place plain-text marker in each text input, submit if appropriate, then search for marker in page DOM.
    Marker is plain text (no tags) to avoid code execution.
    """
    findings = []
    inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text'], input:not([type]), textarea")
    for i, el in enumerate(inputs):
        try:
            el.clear()
            el.send_keys(marker)
            # attempt simple submit if inside a form with submit button present (we avoid submitting if form has action external)
            form = el.find_element(By.XPATH, "ancestor::form")
            action = form.get_attribute("action") or ""
            # only submit if action is empty or local
            if action.strip()=="" or action.startswith("/") or action.startswith(driver.current_url.split("/",3)[0]):
                # try pressing submit button if present
                try:
                    btn = form.find_element(By.CSS_SELECTOR, "input[type=submit], button[type=submit]")
                    btn.click()
                    time.sleep(WAIT_SECONDS)
                except Exception:
                    # fallback: don't submit; just check reflection on page
                    pass
            # scan DOM text for marker
            body_text = driver.execute_script("return document.body.innerText || ''")
            if marker in body_text:
                findings.append({"type":"reflected_text", "input_index": i, "note":"marker found in DOM text"})
        except Exception as e:
            # skip failures
            pass
    return findings

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--out", default="ext_report.json")
    p.add_argument("--active", action="store_true", help="Enable safe active check (lab-only)")
    args = p.parse_args()

    opts = FxOptions()
    opts.headless = True
    driver = webdriver.Firefox(options=opts)  # change to Chrome if preferred and driver present
    try:
        print("[+] Opening", args.url)
        driver.set_page_load_timeout(20)
        driver.get(args.url)
        time.sleep(WAIT_SECONDS)
        report = {"passive": collect_passive(driver, args.url), "active_findings": []}
        if args.active:
            print("[!] Active safe testing enabled — only run in lab/with permission")
            marker = "TEST_MARKER_" + uuid.uuid4().hex[:8]  # plain-text marker
            report["active_findings"] = safe_active_test_reflection(driver, marker)
        # also grab response headers using fetch (same-origin) if available
        try:
            headers = driver.execute_script("""
              return fetch(location.href, {method:'HEAD'}).then(r => r.headers ? Array.from(r.headers.entries()) : []).catch(e=>[['fetch_error', String(e)]]);
            """)
            report["response_headers"] = dict(headers) if isinstance(headers, list) else headers
        except Exception:
            report["response_headers"] = None

        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
        print("[+] Report written to", args.out)
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
