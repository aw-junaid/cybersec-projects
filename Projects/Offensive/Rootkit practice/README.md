# Rootkit Practice (Sandbox) — Create & Remove Benign Rootkits

## Purpose

This project allows students to **study rootkit mechanisms** (hiding processes, files, and network ports) in a **sandboxed environment**:

* Learn **kernel and user-space rootkit concepts** safely.
* Test **detection methods** like `lsmod`, `ps`, `netstat`, `lsof`, and IDS/EDR tools.
* Understand **infection & cleanup** lifecycle in a lab setting.

⚠️ **Safety Note:**

* Only operate inside an **isolated VM or container**.
* The tools **must not modify the host system outside the sandbox**.
* The "rootkit" will **simulate hiding/unhiding** behavior in **temporary directories or virtualized filesystems**.

---

## General Algorithm / Working Logic

###  Rootkit Simulation Algorithm

1. **Safety checks**: Ensure a sandbox path or environment variable is set (`ROOTKIT_SANDBOX=1`). Abort if not.
2. **Create benign “rootkit artifacts”**:

   * Fake hidden processes (simulated with dummy scripts or threads).
   * Hidden files in sandbox folder with special prefix (`.rk_hidden_`).
   * Hidden network ports simulated via local loopback services.
3. **Hiding mechanism**:

   * Move files to hidden folders inside sandbox.
   * Use OS-level tricks (prefixed `.` in Linux) or dummy filters for process listings.
4. **Monitoring / Logging**:

   * Track created artifacts in `rk_log.json`.
5. **Removal / Cleanup**:

   * Restore files and stop dummy processes.
   * Remove all sandbox artifacts safely.

---

### ▶ How to Run (Python)

```bash
export ROOTKIT_SANDBOX=1
mkdir /tmp/sandbox_rootkit
python3 benign_rootkit.py
# Enter sandbox path: /tmp/sandbox_rootkit
# Choose run/cleanup
```


### ▶ How to Compile & Run (C)

```bash
gcc -o benign_rootkit benign_rootkit.c
export ROOTKIT_SANDBOX=1
mkdir /tmp/sandbox_rootkit
./benign_rootkit
# Follow interactive prompts
```

