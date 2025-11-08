## How the Python tool works (algorithm)

1. Launch headless browser (Firefox by default).
2. `GET` the page and wait.
3. Run an in-page JS snippet to collect meta tags, scripts, CSP meta, forms, and inline script counts (passive).
4. Optionally (active, lab-only): place a **plain-text** marker into text inputs and attempt benign submissions; then check whether marker appears in DOM text (indicates reflection). This is **non-executing** and safe when used ethically.
5. Try a `HEAD` fetch to collect response headers (may be blocked by CORS).
6. Output a JSON report.

## Run on Kali

```bash
pip3 install selenium
# install geckodriver or chromedriver and ensure browser is installed (apt install firefox-esr geckodriver)
python3 ext_scanner.py --url http://127.0.0.1:8000 --out report.json
# Lab-only active test:
python3 ext_scanner.py --url http://127.0.0.1:8000 --out report_active.json --active
```


