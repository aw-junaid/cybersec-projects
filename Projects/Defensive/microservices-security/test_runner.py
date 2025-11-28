#!/usr/bin/env python3
import json
import subprocess
import sys
from typing import Dict, List

class SecurityTestRunner:
    def __init__(self):
        self.results = []
    
    def run_test(self, name: str, command: List[str]) -> bool:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            success = result.returncode == 0
            self.results.append({
                "test": name,
                "status": "PASS" if success else "FAIL",
                "output": result.stdout,
                "error": result.stderr
            })
            return success
        except Exception as e:
            self.results.append({
                "test": name,
                "status": "ERROR",
                "output": "",
                "error": str(e)
            })
            return False
    
    def print_results(self):
        print(json.dumps(self.results, indent=2))
        return all(r["status"] == "PASS" for r in self.results)

if __name__ == "__main__":
    runner = SecurityTestRunner()
    
    # Test cases will be implemented in subsequent sections
    tests = [
        ("mTLS Positive", ["curl", "-f", "https://service-b:8080/health"]),
        ("mTLS Negative", ["curl", "--fail", "http://service-b:8080/health"]),
    ]
    
    for name, cmd in tests:
        runner.run_test(name, cmd)
    
    if not runner.print_results():
        sys.exit(1)
