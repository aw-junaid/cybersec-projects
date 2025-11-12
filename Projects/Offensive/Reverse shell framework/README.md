# What this tool is for

A learning tool that simulates the behavior of a reverse-shell framework: connection establishment, authentication, keepalive, framed command/response exchange, and logging — **without executing system shell commands**. Use it in closed labs to teach networking, protocols, and secure design patterns.

# Algorithm / how it works (step-by-step)

1. Server (listener) starts on a configured interface+port (default `127.0.0.1:9000`) and loads an allowed token.
2. Client (agent) connects to server and sends an authentication token. Server validates token.
3. If authenticated, the client receives a prompt; the client and server exchange framed messages (length prefix + JSON) so boundaries are clear.
4. Client sends `command` messages. Server maps commands to a whitelist of *simulated* handlers (e.g., `uname` → fixed output; `whoami` → configured name). No OS execution.
5. Server returns `result` messages (with simulated stdout, stderr, exit_code). All messages are logged to a file with timestamps.
6. Keepalive / ping messages supported; connection closed on invalid token or inactivity.

---

# Python implementation (safe simulator)

Save two files: `sim_server.py` and `sim_client.py`.

How to run (Python):

1. Ensure Python 3.8+ is installed.
2. Start server (in one terminal):

   ```
   python3 sim_server.py --host 127.0.0.1 --port 9000 --token mylabtoken
   ```
3. Start client (in another terminal):

   ```
   python3 sim_client.py --host 127.0.0.1 --port 9000 --token mylabtoken
   ```
4. Try commands: `whoami`, `uname`, `date`, `echo hello`, `help`. Type `exit` to quit.

---

# C implementation (safe simulator, POSIX)

Two files: `sim_server.c` and `sim_client.c`. These are straightforward single-connection examples (no JSON library used — we use a tiny length-prefixed plain text protocol). They **do not** execute commands; they return canned outputs.


How to compile & run (C):

1. Compile:

   ```
   gcc -o sim_server sim_server.c
   gcc -o sim_client sim_client.c
   ```
2. Run server (default binds to localhost):

   ```
   ./sim_server 9000 labtoken
   ```
3. Run client:

   ```
   ./sim_client 127.0.0.1 9000 labtoken
   ```

---

# Notes, limitations, and safe-extension ideas

* **Safety first:** both Python and C versions are intentionally non-malicious — they never run system shell commands. They’re for learning networking, authentication, framing, and logging. Don’t modify them to execute arbitrary commands unless you are in an isolated, consented, and legally permitted lab environment and you clearly understand the risks.
* **Extending safely:** if you want to experiment with more realistic behavior in a controlled lab:

  * Add **mutual TLS** so client/server authenticate using certificates.
  * Replace canned handlers with a **sandboxed interpreter** (e.g., run commands inside a locked-down container with strict resource limits), and ensure strict auditing.
  * Add an **audit trail**: structured logs, sequence numbers, and signed messages.
  * Teach detection/defense: run host-based IDS to detect outgoing reverse connections and practice blocking with egress rules.
* **Testing in a lab:** always run on isolated networks (e.g., VM networks or an air-gapped lab). Use unique tokens and rotate them. Keep the logs for lessons in forensics.
* **If your goal is defensive training**, I can also produce:

  * host/IDS rules to detect reverse-shell-like behavior (suricata/snort examples),
  * egress firewall rule examples,
  * lab exercises and rubrics for students to practice detection and containment.
* **If your goal is remote administration**, consider legitimate, audited tools (SSH, mTLS-controlled agents, management frameworks) instead of ad-hoc reverse shells.
