# Kernel Backdoor Detector/Creator (Lab) — Study Kernel Persistence

## Purpose

This project allows students to **understand kernel-level persistence techniques** in a **sandboxed environment**:

* Simulate kernel backdoors **safely** (without modifying the real kernel).
* Analyze how malicious kernel modules maintain **persistence** and **hide processes or network connections**.
* Test detection strategies: file integrity monitoring, kernel module analysis, audit logs.
* Learn **defensive countermeasures**: module signing enforcement, integrity verification, kernel scanning tools.

⚠️ **Safety Note:**

* Only run in **isolated VMs or containerized labs**.
* **No real kernel modules are loaded**. Instead, we **simulate module behavior** using files, logs, and mock kernel interfaces.

---

## General Algorithm / Working Logic

### Kernel Backdoor Simulation Algorithm

1. **Safety Check**

   * Ensure environment variable `KERNEL_LAB_SANDBOX=1`.
   * Verify sandbox directory exists.
   * Abort otherwise.

2. **Simulated Module Creation**

   * Create a file representing a kernel module (`.ko_sim`) in sandbox.
   * Assign metadata (name, version, load timestamp, simulated export symbols).

3. **Persistence Simulation**

   * Write a "persistence registry" inside sandbox (simulating `/etc/modules-load.d/`).
   * Optionally create "hidden process hooks" and log files mimicking kernel hooks.

4. **Detection / Scanning**

   * Provide a function that scans the sandbox for "loaded kernel modules".
   * Check hashes, timestamps, and hidden flags for anomalies.

5. **Cleanup**

   * Remove simulated modules, hooks, and logs safely.

6. **Optional Exercises**

   * Modify the simulated module to "hide" from scanning tools.
   * Detect hidden artifacts using log analysis, entropy checks, or signature scanning.

---


### ▶ How to Run (Python)

```bash
export KERNEL_LAB_SANDBOX=1
mkdir /tmp/kernel_lab_sandbox
python3 kernel_backdoor_lab.py
# Enter sandbox path: /tmp/kernel_lab_sandbox
# Choose create/detect/cleanup
```

---

## C Implementation (Optional Minimal)

For C, you can simulate modules by creating files, calculating hashes, and writing logs. The workflow is similar:

1. Verify `KERNEL_LAB_SANDBOX=1`.
2. Create `.ko_sim` files.
3. Write persistence JSON.
4. Scan files for hashes.
5. Clean up.

Due to C’s file handling, students can practice **hashing, file scanning, and safe sandbox operations**.

---

## Educational Applications

| Concept                | Lab Task                                                           |
| ---------------------- | ------------------------------------------------------------------ |
| Module creation        | Students create sandbox modules and metadata.                      |
| Persistence simulation | Write "modules-load.d_sim.json" and mimic auto-load behavior.      |
| Detection              | Scan `.ko_sim` files and calculate SHA256 to detect modifications. |
| Cleanup                | Safely remove all simulated artifacts.                             |
| Forensics              | Generate logs for timeline analysis (`kernel_lab_log.json`).       |

