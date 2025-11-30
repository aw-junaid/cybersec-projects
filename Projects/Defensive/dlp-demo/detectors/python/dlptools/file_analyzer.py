#!/usr/bin/env python3
"""
File Analyzer for DLP Demo
Extracts and analyzes files from network streams
LAB USE ONLY - NEVER RUN AGAINST PRODUCTION DATA
"""

import os
import hashlib
import magic
import yara
import math
import tempfile
import json
from typing import Dict, List, Optional
from dlptools.safety import SafetyChecker

class FileAnalyzer:
    def __init__(self, yara_rules_path: str, extract_dir: str = "samples/extracted"):
        SafetyChecker.verify_lab_mode()
        
        self.extract_dir = extract_dir
        os.makedirs(self.extract_dir, exist_ok=True)
        
        # Load YARA rules
        try:
            self.yara_rules = yara.compile(yara_rules_path)
        except Exception as e:
            print(f"Warning: Could not load YARA rules: {e}")
            self.yara_rules = None
        
        self.mime = magic.Magic(mime=True)
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze file for sensitive content"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Basic file info
            file_stat = os.stat(file_path)
            file_hash = hashlib.sha256(data).hexdigest()
            mime_type = self.mime.from_file(file_path)
            
            # YARA scanning
            yara_matches = []
            if self.yara_rules:
                matches = self.yara_rules.match(file_path)
                yara_matches = [str(m) for m in matches]
            
            # Entropy analysis
            entropy = self.entropy(data)
            
            return {
                "file_path": file_path,
                "size": file_stat.st_size,
                "sha256": file_hash,
                "mime_type": mime_type,
                "entropy": entropy,
                "yara_matches": yara_matches,
                "suspicious": entropy > 7.0 or len(yara_matches) > 0
            }
            
        except Exception as e:
            return {
                "file_path": file_path,
                "error": str(e),
                "suspicious": False
            }
    
    def extract_from_http(self, http_data: bytes, filename: str) -> Optional[Dict]:
        """Extract file from HTTP data"""
        try:
            extract_path = os.path.join(self.extract_dir, filename)
            
            with open(extract_path, 'wb') as f:
                f.write(http_data)
            
            return self.analyze_file(extract_path)
            
        except Exception as e:
            print(f"Error extracting HTTP file: {e}")
            return None
    
    def entropy(self, data):
        """Calculate byte entropy"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

if __name__ == "__main__":
    # Safety check
    SafetyChecker.verify_lab_mode()
    
    # Test the analyzer
    analyzer = FileAnalyzer("yara/exfil_signatures.yar")
    
    # Create test file
    test_data = b"fake credit card: 4111-1111-1111-1111"
    test_path = "test_file.txt"
    
    with open(test_path, 'wb') as f:
        f.write(test_data)
    
    result = analyzer.analyze_file(test_path)
    print(json.dumps(result, indent=2))
    
    # Cleanup
    os.remove(test_path)
