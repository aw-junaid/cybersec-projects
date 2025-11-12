## How it works — high level (algorithm)

1. Accept a target URL that contains a parameter to test (e.g. `http://127.0.0.1:8000/search?q=term`).
2. For each test payload:

   * send a **baseline** request (clean value) and record response body hash/length/status.
   * send a **payload** request (inject test string) and record response.
   * compare responses: if they differ in predictable ways (different body, different error messages, SQL error strings), mark as *possible* SQLi.
3. Report findings with contextual info (parameter, payload, evidence).

---


### How to use (Python)

1. Create a local vulnerable test target. Recommended: install DVWA, bWAPP, or use a small Flask sample (below).
2. Run the scanner:

```bash
python3 -m pip install requests
python3 sqli_tester.py --url "http://127.0.0.1:8000/search?q=foo" --out local_report.json
```

3. Inspect `local_report.json` for `evidence` items. `boolean_difference` indicates that the `true` vs `false` payloads produced different responses — a *possible* sign of injectable parameter.

---

## Minimal vulnerable test target (safe lab) — tiny Flask app

If you don’t have DVWA, use this tiny intentionally vulnerable app for testing (only run in a VM):

Save as `vuln_app.py`:

Run:

```bash
python3 -m pip install flask
python3 vuln_app.py
# Test at http://127.0.0.1:8000/search?q=alice
```

Then run the Python tester against `http://127.0.0.1:8000/search?q=test`.

---


### Compile & run (C)

```bash
sudo apt update
sudo apt install -y libcurl4-openssl-dev libssl-dev build-essential
gcc -o sqli_tester sqli_tester.c -lcurl -lssl -lcrypto
./sqli_tester "http://127.0.0.1:8000/search?q=test"
```

The C tool prints evidence lines like `SQL error strings detected` or `true/false responses differ` to indicate possible injection.

---

## What these tools *do not* do

* They do **not** extract data from databases.
* They do **not** try time-based blind exploitation (which can be slow and intrusive).
* They do **not** run multi-step exploit chains to enumerate columns/tables automatically.
  If you need controlled exploit demonstrations for teaching, do them manually in a lab with a pre-seeded DB and limit queries to safe checks only.

---

## Interpreting results — false positives & next steps

* **False positives are common**. Differences can be caused by caching, load balancers, or application logic. Always validate manually.
* If boolean tests show differences, try:

  * repeat tests
  * use different unique markers
  * check HTTP response headers, cookies, and server-side error pages
* For safe, deeper analysis use authorized labs (DVWA) and manual verification with a browser or proxy (Burp) while observing logs.

---

## Defensive uses & mitigations

If you’re on the defending side, use these techniques to:

* detect parameters that reflect user input unescaped,
* ensure prepared statements / parameterized queries are used,
* remove verbose SQL error messages in production,
* enforce least privilege DB accounts and input validation.

---

