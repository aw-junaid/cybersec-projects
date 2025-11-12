# Design & algorithm

Purpose: simulate ransomware *behavioral patterns* (file discovery, “encrypting” files, ransom note creation, persistence attempt, C2 beacon simulation) without destructive effects.

Algorithm:

1. **Safety checks** (MUST pass):

   * Simulator runs only when `--sandbox-dir` is provided and points to an existing, empty directory created by the user.
   * The sandbox directory name must contain the token string `sandbox_sim`.
   * An environment variable `SIM_RUN_ALLOWED=1` must be set (clear manual opt-in).
   * Simulator refuses to run otherwise.
2. **Discovery**: recursively enumerate files under sandbox, respecting a whitelist of extensions (`.txt`, `.pdf.sample`, `.docx.sample` — not real docs) and size limits.
3. **Simulated encryption**: for each file, create a copy `filename.encsim` containing an XOR with a fixed key *only* (simple reversible transform). Original files are left unchanged unless `--overwrite` is explicitly passed (but even then, overwrite only created-by-simulator temp files).
4. **Ransom note**: create a human-readable ransom note `README_RECOVER.txt` inside sandbox.
5. **Telemetry / logging**: write a structured JSON log of actions (timestamps, filenames, sizes, actions). Optionally emit simulated network beacon events to `localhost` on a configured port (so IDS can capture).
6. **Persistence simulation**: emulate an attempt to install persistence by writing a benign marker file (e.g., `~/.local/share/sim_persist`) in the sandbox (not system locations).
7. **Teardown / revert**: provide a safe revert mode to restore original files from `.encsim` copies (XOR again) — can only be run within sandbox and requires the same environment variable.
8. **Dry-run**: show planned actions without writing anything.

---

# Python simulator

Save as `ransom_sim.py`.

# How to prepare and run (Python)

1. Create an isolated VM or container snapshot you can revert.
2. In the VM, make an empty sandbox directory you control:

   ```bash
   mkdir -p /tmp/sandbox_sim_exercise
   ```
3. Place a few small sample files (text files) inside the sandbox — **ONLY** files you created for the lab:

   ```bash
   echo "secret1" > /tmp/sandbox_sim_exercise/a1.txt
   echo "notes" > /tmp/sandbox_sim_exercise/b2.sample
   ```
4. Export the allow environment variable (explicit consent):

   ```bash
   export SIM_RUN_ALLOWED=1
   ```
5. Dry-run to see planned actions:

   ```bash
   python3 ransom_sim.py --sandbox-dir /tmp/sandbox_sim_exercise --dry-run
   ```
6. Run live simulation (writes `.encsim` copies, ransom note, logs):

   ```bash
   python3 ransom_sim.py --sandbox-dir /tmp/sandbox_sim_exercise --beacon-port 12345
   ```
7. To revert:

   ```bash
   python3 ransom_sim.py --sandbox-dir /tmp/sandbox_sim_exercise --revert
   ```

**Important**: the script will abort if the sandbox path does not contain `sandbox_sim` or if `SIM_RUN_ALLOWED` is not set. This reduces accidental misuse.

---

# Minimal C simulator (safe, educational)

This C program implements a much smaller safe simulator: it verifies sandbox path contains `sandbox_sim`, requires `SIM_RUN_ALLOWED=1`, finds `.txt` files and writes `.encsim` XOR copies. Save as `ransom_sim_min.c`.


Compile & run:

```bash
gcc -o ransom_sim_min ransom_sim_min.c
# prepare a sandbox dir named with 'sandbox_sim' and put a few .txt files
export SIM_RUN_ALLOWED=1
./ransom_sim_min /tmp/sandbox_sim_ex
```

---

# Detection, telemetry & forensic exercises

Use the simulator to teach detection and analysis. Example exercises & artefacts to collect:

1. **Host activity**

   * Run `strace` / `dtruss` / `procmon` while simulator runs and capture system calls (open/read/write/unlink). Students should identify high-rate file writes and the creation of `.encsim` files and ransom note.
   * Use `auditd` to log `open`, `rename`, `chmod` syscalls in the sandbox.

2. **Network telemetry**

   * Simulator can optionally send a UDP beacon to `127.0.0.1:PORT`. Run `tcpdump -i lo udp port PORT -w beacon.pcap` to capture beacon payloads (JSON-like).
   * Create a Suricata rule to detect the beacon pattern: (see example below).

3. **File artefacts & YARA**

   * Write YARA rules that match ransom note text or `.encsim` suffix.
   * Example simple YARA:

     ```
     rule sim_ransom_note {
       strings:
         $a = "This is a safe lab simulation" ascii
       condition:
         $a
     }
     ```

4. **IDS / Suricata example (beacon UDP)**

   * Suricata rule (example):

     ```
     alert udp any any -> 127.0.0.1 12345 (msg:"SIM_RANSOM_SIM_BEACON"; content:"\"event\":\"beacon\""; sid:1000001; rev:1; classtype:trojan-activity;)
     ```

5. **Sigma rule idea (host detection)**

   * Detect creation of many `.encsim` files in a short time under user directories, or new files named `README_RECOVER.txt`. Use host logs (Sysmon on Windows) to detect mass file write events.

6. **Forensic timeline**

   * Students should build a timeline from logs: file creation times, process execution, network beacons. Use `plaso` or `log2timeline` on collected logs.

7. **Mitigations lab**

   * Show how EDR blocks: create rules to block processes that attempt to write `.encsim` files or write many files quickly. Practice containment: kill process, block egress, restore from backups.

8. **Audit / hardening tasks**

   * Demonstrate safe file-system permissions (no world-writable directories), restrict user write privileges, enable app whitelisting, egress filtering.


# Limitations & instructor notes

* This simulator is intentionally simple and not real ransomware: it uses XOR and writes copies to demonstrate behavior. Do **not** use it on real data.
* For more realistic lab work (where instructors desire realistic cryptography and sandboxed destructive behavior), run a controlled lab appliance or container with disposable storage and instructor supervision, and consider using hardened sandboxing (LXC/Firecracker) and system snapshots.
* If you plan to expand the simulator (e.g., simulate privilege escalation, more sophisticated persistence), keep the same safety constraints (explicit opt-in, sandbox path checks, VM-only).


