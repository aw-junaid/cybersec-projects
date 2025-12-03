"""
Honeyfile Management
Create and monitor decoy files to detect ransomware activity
"""

import os
import json
import time
import logging
import hashlib
from threading import Thread, Lock

class HoneyfileManager:
    def __init__(self, honeyfiles_file, alert_manager):
        self.honeyfiles_file = honeyfiles_file
        self.alert_manager = alert_manager
        self.honeyfiles = {}
        self.lock = Lock()
        self.logger = logging.getLogger("HoneyfileManager")
        self.load_honeyfiles_config()
    
    def load_honeyfiles_config(self):
        """Load honeyfile configuration"""
        try:
            if os.path.exists(self.honeyfiles_file):
                with open(self.honeyfiles_file, 'r') as f:
                    self.honeyfile_locations = [line.strip() for line in f if line.strip()]
            else:
                # Default honeyfile locations
                self.honeyfile_locations = [
                    '/home/user/documents/important_passwords.txt',
                    '/home/user/documents/financial_records.xlsx',
                    '/home/user/documents/private_photos.zip'
                ]
                self._create_default_config()
        except Exception as e:
            self.logger.error(f"Error loading honeyfiles config: {e}")
            self.honeyfile_locations = []
    
    def _create_default_config(self):
        """Create default honeyfiles configuration"""
        os.makedirs(os.path.dirname(self.honeyfiles_file), exist_ok=True)
        with open(self.honeyfiles_file, 'w') as f:
            for location in self.honeyfile_locations:
                f.write(location + '\n')
    
    def create_honeyfiles(self):
        """Create honeyfiles in specified locations"""
        for location in self.honeyfile_locations:
            try:
                dir_path = os.path.dirname(location)
                os.makedirs(dir_path, exist_ok=True)
                
                # Create realistic-looking content based on file extension
                content = self._generate_honeyfile_content(location)
                
                with open(location, 'w') as f:
                    f.write(content)
                
                # Store hash for integrity checking
                file_hash = self._calculate_file_hash(location)
                self.honeyfiles[location] = {
                    'hash': file_hash,
                    'created': time.time(),
                    'size': len(content)
                }
                
                self.logger.info(f"Created honeyfile: {location}")
                
            except Exception as e:
                self.logger.error(f"Failed to create honeyfile {location}: {e}")
    
    def _generate_honeyfile_content(self, file_path):
        """Generate realistic-looking honeyfile content"""
        ext = os.path.splitext(file_path)[1].lower()
        
        content_generators = {
            '.txt': self._generate_text_content,
            '.doc': self._generate_doc_like_content,
            '.xlsx': self._generate_excel_like_content,
            '.pdf': self._generate_pdf_like_content,
            '.zip': self._generate_zip_like_content
        }
        
        generator = content_generators.get(ext, self._generate_text_content)
        return generator()
    
    def _generate_text_content(self):
        """Generate realistic text file content"""
        return """Important Passwords and Accounts:
        
Bank Account: **** **** **** 1234
Email: user@company.com
SSH Key: ssh-rsa AAAAB3NzaC1yc2E...
Database Password: SuperSecret123!

DO NOT DELETE OR MODIFY THIS FILE."""
    
    def _generate_doc_like_content(self):
        """Generate content that looks like a Word document"""
        # This would be binary in real implementation
        return "Microsoft Word Document - Confidential"
    
    def _generate_excel_like_content(self):
        """Generate content that looks like Excel data"""
        return "Financial Records 2024 - Confidential Business Data"
    
    def _generate_pdf_like_content(self):
        """Generate PDF-like content"""
        return "%PDF-1.4\nConfidential Document - Do Not Modify"
    
    def _generate_zip_like_content(self):
        """Generate ZIP-like content"""
        return "PK\x03\x04PrivatePhotosArchive"
    
    def _calculate_file_hash(self, file_path):
        """Calculate file hash for integrity checking"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""
    
    def is_honeyfile(self, file_path):
        """Check if a file is a honeyfile"""
        return file_path in self.honeyfile_locations
    
    def check_honeyfile_integrity(self):
        """Periodically check honeyfile integrity"""
        with self.lock:
            for location in self.honeyfile_locations:
                if os.path.exists(location):
                    current_hash = self._calculate_file_hash(location)
                    original_hash = self.honeyfiles.get(location, {}).get('hash')
                    
                    if original_hash and current_hash != original_hash:
                        self.alert_manager.alert(
                            "CRITICAL",
                            f"Honeyfile integrity compromised: {location}",
                            {
                                "file_path": location,
                                "original_hash": original_hash,
                                "current_hash": current_hash
                            }
                        )
                else:
                    self.alert_manager.alert(
                        "CRITICAL",
                        f"Honeyfile deleted: {location}",
                        {"file_path": location}
                    )
    
    def start_integrity_monitoring(self, interval=60):
        """Start periodic integrity checking"""
        def monitor_loop():
            while True:
                time.sleep(interval)
                self.check_honeyfile_integrity()
        
        monitor_thread = Thread(target=monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def cleanup(self):
        """Remove honeyfiles (optional)"""
        if os.environ.get('CLEANUP_HONEYFILES') == 'true':
            for location in self.honeyfile_locations:
                try:
                    if os.path.exists(location):
                        os.remove(location)
                        self.logger.info(f"Cleaned up honeyfile: {location}")
                except Exception as e:
                    self.logger.error(f"Error cleaning up honeyfile {location}: {e}")
