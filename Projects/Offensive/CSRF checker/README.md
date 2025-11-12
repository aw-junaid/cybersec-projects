# What this tool is for

Detect common CSRF weaknesses on a web page by scanning forms and cookies for typical protections (anti-CSRF tokens, SameSite flags, Referer checks, and unsafe state-changing GET endpoints). Useful for students to learn how CSRF protections are implemented and which pages may need additional protection.

# Algorithm / how it works (general, step-by-step)

1. Accept a target URL. Perform an HTTP GET to retrieve the page HTML and cookies.
2. Parse HTML and extract all `<form>` elements. For each form:

   * Record `action`, `method` (default GET), and list of input fields.
   * Check if form contains hidden inputs with names or ids commonly used for CSRF tokens (e.g., `csrf`, `csrf_token`, `authenticity_token`, `__RequestVerificationToken`, `token`, etc.). If present → mark token found.
   * If method is `POST` and no token found → mark as *potentially vulnerable*.
3. Inspect cookies supplied by the server:

   * For each cookie, check if `SameSite` attribute is set (Strict or Lax). Lack of SameSite may indicate weaker CSRF protection.
   * Check if `HttpOnly` and `Secure` flags exist (not direct CSRF protection, but relevant).
4. Heuristic: look for links or forms that perform state-changing actions via GET (URLs containing `/delete`, `/logout`, `/transfer`, or query parameters that indicate actions). Any state-changing GET endpoints are flagged as high risk.
5. Produce a concise report of findings with recommendations (add anti-CSRF token, set SameSite/Lax or Strict, avoid state-changing GETs, verify Referer/origin server-side).

# Python implementation (educational, uses `requests` + `bs4`, read-only)

How to run (Python):

1. Install dependencies:

   ```bash
   pip install requests beautifulsoup4
   ```
2. Run:

   ```bash
   python3 csrf_checker.py https://example.com/page
   ```

# C implementation (educational, uses libcurl + simple string checks)

Save as `csrf_checker.c`. This is intentionally conservative: it performs a GET using libcurl and applies simple substring/regex-like checks for hidden inputs and cookie attributes. Parsing HTML properly in C is heavy; this provides teaching value and portability.


## How to compile & run (C):

1. Install libcurl (on Debian/Ubuntu):

   ```bash
   sudo apt-get install libcurl4-openssl-dev
   ```
2. Compile:

   ```bash
   gcc -o csrf_checker csrf_checker.c -lcurl
   ```
3. Run (read-only):

   ```bash
   ./csrf_checker https://example.com/login
   ```

# Notes / limitations / safe-use reminders

* **Non-destructive:** both implementations only perform `GET` requests and passive parsing. They do **not** submit forms or attempt to exploit vulnerabilities.
* **Heuristic scanning:** detection is heuristic — hidden token names vary widely; frameworks embed tokens in meta tags or JavaScript. False negatives (missed tokens) and false positives (token-like fields that are not CSRF protections) are possible.
* **SameSite detection:** for full cookie attribute accuracy, server `Set-Cookie` headers must be visible in the response. Some environments (reverse proxies, JS-managed cookies) can hide or change header behavior.
* **State-changing GET detection:** we use simple keyword heuristics (`/delete`, `/logout` etc.). This can flag benign links or miss poorly-named endpoints. Manual follow-up is required.
* **Legal & ethical:** only test sites you own or have explicit permission to test. Unauthorized scanning may violate terms of service or laws. Always follow responsible disclosure when you find a real issue.
* **Improvements you can add:** richer HTML parsing (JS execution with headless browser to detect tokens set by JavaScript), Origin/Referer checking tests (with permission and non-destructive methods), integration with CSRF token pattern databases, chaining to authenticated sessions (with explicit credentials) for deeper testing.

---

