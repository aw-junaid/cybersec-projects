# What this tool is for

A controlled uploader for lab environments to demonstrate how file uploads are performed and defended against: authentication, size limits, content-type checking, filename sanitization, storage policies, and audit logging — **without executing** uploaded files.

---

# Algorithm / how it works (general)

1. Server starts and listens (HTTP on localhost or a lab subnet). Loads allowed token and allowed extensions (by default: `.txt`, `.jpg`, `.png`, `.safe`). Max upload size enforced.
2. Client takes a local file, optionally checks extension and size, and issues an authenticated multipart/form-data POST to `/upload`.
3. Server authenticates token (header or form field). If invalid → reject.
4. Server validates file: size, extension, content-type (basic) and scans for ASCII-only or simple signatures if requested.
5. Server sanitizes filename (strip path chars, normalize), appends `.safe`, stores under `uploads/` with 0600 file mode, and logs uploader IP, filename, original size, and timestamp.
6. Server returns JSON with status and stored filename. Client prints result.
7. Server never sets uploaded files executable and never runs them. Optionally a separate controlled "analysis" tool (manual) can inspect stored files.

---

# Python implementation (recommended for labs)

Two files: `uploader_server.py` and `uploader_client.py`.

## How to run (Python)

1. Install deps:

```bash
pip install flask python-magic requests
# On some systems python-magic may require libmagic: e.g., apt-get install libmagic-dev
```

2. Start server (terminal 1):

```bash
python3 uploader_server.py --host 127.0.0.1 --port 8000 --token labtoken123
```

3. Upload a file (terminal 2):

```bash
python3 uploader_client.py --host 127.0.0.1 --port 8000 --token labtoken123 sample.txt
```

4. Inspect `uploads/` directory. Files are saved with `.safe` suffix and mode `0600`.

---

# C implementation

Provide a C **client** that uploads via HTTP multipart using `libcurl`, and a minimal **C server** that listens on a TCP port and accepts a small custom upload protocol (length-prefixed filename + base64 body). The C-server approach avoids serving a full HTTP stack (keeps it educational). *Neither executes uploaded files.*


Compile & run:

```bash
gcc -o upload_client upload_client.c -lcurl
./upload_client http://127.0.0.1:8000/upload labtoken123 sample.txt
```

## C server (custom, minimal, `upload_server_minimal.c`)

This server implements a tiny proprietary protocol on TCP port: client sends 4-byte fname length, fname bytes (UTF-8), 8-byte content length (network order), then the file bytes. Server writes file with `.safe` suffix and 0600 mode. This is educational — not HTTP.


Compile & run:

```bash
gcc -o upload_server_minimal upload_server_minimal.c
./upload_server_minimal 9001 labtoken123
```

Client (toy protocol) would need to be written to match this custom protocol; prefer the libcurl client for HTTP tests with the Python server.

---

# Notes, limitations, and ethics

* **No execution ever**: both server implementations explicitly avoid executing uploaded content. Files are saved with `.safe` suffix and `0600` permissions. Do not change this unless you understand the risks.
* **Auth & limits**: use tokens, bind to localhost or lab subnets, enforce size limits and allowed extensions. Rotate tokens frequently.
* **Sanitization**: filenames are sanitized to prevent path traversal. Content-type sniffing is basic — in real systems use deep scanning, antivirus, and sandbox analysis for suspicious files.
* **Logging**: all uploads are logged; keep logs for audits.
* **Testing environment**: run in VMs or an isolated VLAN. Do not expose to the public Internet.
* **Extensions for learning** (lab-safe):

  * Add a quarantine/analysis queue — files go to quarantine and are inspected by a safe analyzer (no dynamic execution).
  * Demonstrate E2E signing: client signs uploads and server verifies signature.
  * Show detection: integrate with a host-based IDS or YARA rules to flag suspicious patterns.
  * Build a web UI that lists uploaded files and their metadata for students to review (read-only).
  * Teach mitigation: show how a misconfigured uploader (no size checks, no sanitization) can be abused — but only in an isolated classroom VM.

---
