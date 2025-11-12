#!/usr/bin/env python3
"""
ransom_sim.py - SAFE Ransomware Simulator (lab-only)

-- SAFETY: This tool will REFUSE to run unless ALL of the following are true:
  * You pass --sandbox-dir which points to an existing directory you created.
  * The sandbox directory path contains the substring "sandbox_sim".
  * You set the environment variable SIM_RUN_ALLOWED=1 before running.
  * The sandbox directory must be empty (or created specifically for this run) unless --allow-nonempty is supplied (for advanced lab instructors).

This simulator does NOT encrypt real user files. It writes reversible XOR'd copies with suffix ".encsim"
and leaves originals intact by default. It will produce logs and a ransom note inside the sandbox.
Use only inside isolated VMs, containers, or air-gapped lab networks.
"""

import argparse, os, sys, json, time, pathlib, socket
from datetime import datetime

# -- Configurable parameters --
XOR_KEY = b"sim_k3y"               # reversible key used for demo (not real crypto)
ALLOWED_EXTS = {".txt", ".sample", ".log"}   # whitelist for demo files
MAX_FILE_SIZE = 2 * 1024 * 1024     # 2 MB max for simulation
RANSOM_NOTE = "README_RECOVER.txt"
LOG_FILE = "sim_actions.jsonl"      # line-delimited JSON events

# -- Safety checks --
def safety_checks(sandbox_dir, allow_nonempty):
    if os.environ.get("SIM_RUN_ALLOWED") != "1":
        print("[!] Environment variable SIM_RUN_ALLOWED not set to '1'. Aborting.")
        return False
    if "sandbox_sim" not in os.path.abspath(sandbox_dir):
        print("[!] Sandbox path must include 'sandbox_sim' to avoid accidental runs. Aborting.")
        return False
    if not os.path.isdir(sandbox_dir):
        print("[!] Provided sandbox directory does not exist or is not a directory.")
        return False
    # check emptiness (allow instructors override)
    contents = [p for p in pathlib.Path(sandbox_dir).iterdir() if not p.name.startswith(".sim_meta")]
    if contents and not allow_nonempty:
        print("[!] Sandbox directory is not empty. Create a fresh empty directory for the simulator or use --allow-nonempty (instructor only). Aborting.")
        return False
    return True

# -- Utility: XOR transform (reversible) --
def xor_bytes(data, key):
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

# -- Walk sandbox and collect candidate files --
def discover_files(sandbox_dir):
    candidates = []
    for root, dirs, files in os.walk(sandbox_dir):
        for fname in files:
            # skip simulator artifacts
            if fname.endswith(".encsim") or fname == RANSOM_NOTE or fname == LOG_FILE:
                continue
            path = os.path.join(root, fname)
            try:
                st = os.stat(path)
            except Exception:
                continue
            if st.st_size > MAX_FILE_SIZE:
                continue
            ext = pathlib.Path(fname).suffix.lower()
            if ext not in ALLOWED_EXTS:
                continue
            candidates.append(path)
    return candidates

# -- Logging helper: append JSON lines --
def log_event(sandbox_dir, event):
    path = os.path.join(sandbox_dir, LOG_FILE)
    event['ts'] = datetime.utcnow().isoformat() + "Z"
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

# -- Simulated network beacon (localhost, ephemeral) --
def send_beacon(port, payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload.encode("utf-8"), ("127.0.0.1", port))
        s.close()
        return True
    except Exception:
        return False

def run_simulation(sandbox_dir, dry_run, beacon_port, overwrite):
    print("[*] Starting simulator in sandbox:", sandbox_dir)
    files = discover_files(sandbox_dir)
    print(f"[*] Found {len(files)} candidate(s) for simulated encryption.")

    log_event(sandbox_dir, {"action":"start", "candidates":len(files), "mode":"dry-run" if dry_run else "live"})

    for path in files:
        rel = os.path.relpath(path, sandbox_dir)
        print(f" - [{rel}]")
        log_event(sandbox_dir, {"action":"candidate", "path":rel, "size":os.path.getsize(path)})
        # read
        with open(path, "rb") as f:
            data = f.read()
        # transform (XOR) -> write to .encsim file
        transformed = xor_bytes(data, XOR_KEY)
        out_path = path + ".encsim"
        if dry_run:
            print(f"   (dry-run) would write {os.path.relpath(out_path, sandbox_dir)} size={len(transformed)}")
        else:
            # write atomically
            tmp = out_path + ".tmp"
            with open(tmp, "wb") as g:
                g.write(transformed)
            os.chmod(tmp, 0o600)
            os.replace(tmp, out_path)
            print(f"   wrote {os.path.relpath(out_path, sandbox_dir)}")
            log_event(sandbox_dir, {"action":"wrote_enc", "path":os.path.relpath(out_path, sandbox_dir), "orig":rel})
        # optional overwrite flag: replace original with marker (we keep a backup copy)
        if overwrite and not dry_run:
            backup = path + ".bak_sim"
            if not os.path.exists(backup):
                os.replace(path, backup)
                # create small marker file at original path
                with open(path, "w", encoding="utf-8") as m:
                    m.write("[SIMULATOR] original moved to " + os.path.basename(backup) + "\n")
                os.chmod(path, 0o600)
                log_event(sandbox_dir, {"action":"overwrite_marker", "path":os.path.relpath(path, sandbox_dir)})
    # create ransom note
    ransom_text = (
        "Your files have been simulated-encrypted for analysis.\n"
        "This is a safe lab simulation — no real encryption was performed.\n"
        "To recover files, use the provided simulator revert mode in the same sandbox.\n"
        "Contact: lab-admin@example.local\n"
    )
    note_path = os.path.join(sandbox_dir, RANSOM_NOTE)
    if dry_run:
        print(f"(dry-run) would write ransom note: {RANSOM_NOTE}")
    else:
        with open(note_path, "w", encoding="utf-8") as n:
            n.write(ransom_text)
        os.chmod(note_path, 0o600)
        print(f"[+] Wrote ransom note: {RANSOM_NOTE}")
        log_event(sandbox_dir, {"action":"ransom_note", "path":RANSOM_NOTE})
    # simulated persistence marker
    persist_marker = os.path.join(sandbox_dir, ".sim_persist_marker")
    if dry_run:
        print("(dry-run) would create persistence marker")
    else:
        with open(persist_marker, "w", encoding="utf-8") as p:
            p.write("simulated persistence artifact\n")
        os.chmod(persist_marker, 0o600)
        log_event(sandbox_dir, {"action":"persistence_marker", "path":os.path.relpath(persist_marker, sandbox_dir)})
    # simulated beacon
    if beacon_port:
        payload = json.dumps({"event":"beacon","sandbox":os.path.basename(sandbox_dir),"ts":datetime.utcnow().isoformat()+"Z"})
        ok = send_beacon(beacon_port, payload)
        log_event(sandbox_dir, {"action":"beacon", "port":beacon_port, "ok":ok})
        print(f"[*] Beacon sent to 127.0.0.1:{beacon_port} ok={ok}")
    log_event(sandbox_dir, {"action":"end", "dry_run":dry_run})
    print("[*] Simulation complete. Logs written to", os.path.join(sandbox_dir, LOG_FILE))

def revert_simulation(sandbox_dir, dry_run):
    print("[*] Revert mode: scanning for .encsim files in", sandbox_dir)
    files = []
    for root, dirs, filenames in os.walk(sandbox_dir):
        for fname in filenames:
            if fname.endswith(".encsim"):
                files.append(os.path.join(root, fname))
    print(f"[*] Found {len(files)} .encsim files")
    for enc in files:
        orig = enc[:-7]   # remove .encsim
        rel = os.path.relpath(orig, sandbox_dir)
        if dry_run:
            print(f"(dry-run) would restore {rel} from {os.path.relpath(enc, sandbox_dir)}")
        else:
            with open(enc, "rb") as f:
                data = f.read()
            restored = xor_bytes(data, XOR_KEY)
            tmp = orig + ".rest.tmp"
            with open(tmp, "wb") as g:
                g.write(restored)
            os.chmod(tmp, 0o600)
            os.replace(tmp, orig)
            print(f"[+] Restored {rel}")
            log_event(sandbox_dir, {"action":"restored", "path":rel})
    print("[*] Revert complete.")

def main():
    p = argparse.ArgumentParser(description="SAFE Ransomware Simulator (lab-only)")
    p.add_argument("--sandbox-dir", required=True, help="Path to an existing empty sandbox directory containing 'sandbox_sim'")
    p.add_argument("--dry-run", action="store_true", help="Show planned actions without writing")
    p.add_argument("--beacon-port", type=int, default=0, help="If set, send a UDP beacon to localhost:PORT (for IDS capture)")
    p.add_argument("--revert", action="store_true", help="Revert simulated encryption (must run in same sandbox)")
    p.add_argument("--allow-nonempty", action="store_true", help="Instructor override to allow non-empty dir")
    p.add_argument("--overwrite", action="store_true", help="In live mode, move originals to .bak_sim and add a marker (still safe; originals preserved)")
    args = p.parse_args()

    if not safety_checks(args.sandbox_dir, args.allow_nonempty):
        sys.exit(2)

    if args.revert:
        revert_simulation(args.sandbox_dir, args.dry_run)
    else:
        run_simulation(args.sandbox_dir, args.dry_run, args.beacon_port, args.overwrite)

if __name__ == "__main__":
    main()
