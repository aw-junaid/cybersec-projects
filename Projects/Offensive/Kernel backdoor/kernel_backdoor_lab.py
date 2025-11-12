#!/usr/bin/env python3
"""
Kernel Backdoor Simulator & Detector (Sandbox-only)
Educational lab tool to study kernel persistence safely.
"""

import os
import json
from pathlib import Path
from datetime import datetime
import hashlib

SANDBOX_ENV = "KERNEL_LAB_SANDBOX"
LOG_FILE = "kernel_lab_log.json"

def safety_check():
    if os.environ.get(SANDBOX_ENV) != "1":
        print("[!] KERNEL_LAB_SANDBOX env not set. Abort.")
        exit(1)

def create_sim_module(sandbox_dir, name, version="1.0"):
    module_path = Path(sandbox_dir) / f"{name}.ko_sim"
    content = f"Simulated kernel module {name}\nVersion: {version}\nLoaded: {datetime.utcnow()}"
    with open(module_path, "w") as f:
        f.write(content)
    print(f"[+] Simulated module created: {module_path}")
    return str(module_path)

def log_action(sandbox_dir, action, artifact):
    log_path = Path(sandbox_dir) / LOG_FILE
    entry = {"action": action, "artifact": artifact, "ts": datetime.utcnow().isoformat()}
    logs = []
    if log_path.exists():
        with open(log_path, "r") as f:
            logs = json.load(f)
    logs.append(entry)
    with open(log_path, "w") as f:
        json.dump(logs, f, indent=2)

def simulate_persistence(sandbox_dir, module_path):
    persistence_file = Path(sandbox_dir) / "modules-load.d_sim.json"
    data = {"persistent_modules":[Path(module_path).name]}
    with open(persistence_file, "w") as f:
        json.dump(data, f)
    print(f"[+] Persistence simulated: {persistence_file}")
    return str(persistence_file)

def detect_modules(sandbox_dir):
    print("[*] Scanning sandbox for simulated modules...")
    modules = list(Path(sandbox_dir).glob("*.ko_sim"))
    for m in modules:
        print(f"[+] Found simulated module: {m.name}")
        with open(m, "r") as f:
            data = f.read()
        h = hashlib.sha256(data.encode()).hexdigest()
        print(f"    SHA256: {h}")
        log_action(sandbox_dir, "scan_detect_module", str(m))

def cleanup(sandbox_dir):
    print("[*] Cleaning up simulated modules and persistence...")
    for f in Path(sandbox_dir).glob("*.ko_sim"):
        f.unlink()
        print(f"[-] Removed {f}")
    persistence = Path(sandbox_dir) / "modules-load.d_sim.json"
    if persistence.exists():
        persistence.unlink()
        print(f"[-] Removed persistence file {persistence}")
    log_file = Path(sandbox_dir) / LOG_FILE
    if log_file.exists():
        log_file.unlink()
        print(f"[-] Removed log file {log_file}")

def main():
    safety_check()
    sandbox_dir = input("Enter sandbox directory: ").strip()
    if not Path(sandbox_dir).exists():
        print("[!] Sandbox directory does not exist.")
        exit(1)

    choice = input("Choose action (create/detect/cleanup): ").strip().lower()
    if choice == "create":
        name = input("Module name: ").strip()
        module = create_sim_module(sandbox_dir, name)
        simulate_persistence(sandbox_dir, module)
    elif choice == "detect":
        detect_modules(sandbox_dir)
    elif choice == "cleanup":
        cleanup(sandbox_dir)
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
