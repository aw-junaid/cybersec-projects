### How this Python simulator is safe

* **No SMTP**: it does not send emails. It writes email HTML files to `./emails/` for you to open locally or show in a controlled demo.
* **Landing pages are local**: served only on `127.0.0.1:5000` by default. They log only: timestamp, campaign id, client IP (typically `127.0.0.1` in lab), whether the submitted token matched, and the length of the submitted text (we explicitly **do not** store the raw submission to avoid collecting credentials).
* You can open an email HTML file locally (double-click), or show it in an offline classroom environment.

### How to run (Kali)

```bash
# create venv (optional)
python3 -m venv .venv
source .venv/bin/activate
pip install flask

# run
python3 phish_simulator.py
# Open http://127.0.0.1:5000 in a browser on the same machine (or port-forward from an isolated VM).
```

---


### How to use the C server (lab)

```bash
# compile
gcc -o phish_server phish_server.c

# prepare a landing page
mkdir -p www logs
cat > www/index.html <<'HTML'
<!doctype html><html><body>
<h2>Simulated Login Page</h2>
<form method="post" action="/submit">
<input name="user"/><br/>
<input name="pass" type="password"/><br/>
<button type="submit">Login</button>
</form>
<p>This is a local simulation. Do not enter real credentials.</p>
</body></html>
HTML

# run (bind to high port if unprivileged)
./phish_server 8080

# Open http://127.0.0.1:8080/ in browser and submit test token
# Logs written to logs/phish_c.log
```

This server **does not** write request bodies to disk; it simply logs method/path/client/time to minimize risk. If you need to inspect payloads for exercise grading, store only metadata or hashed/length-only info — never raw credentials.

---



