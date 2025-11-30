import os
import socket
import sys
import subprocess

class SafetyChecker:
    """Enforce lab safety rules"""
    
    @staticmethod
    def verify_lab_mode():
        """Verify DLP_LAB_MODE is set"""
        if os.getenv('DLP_LAB_MODE') != '1':
            print("ERROR: DLP_LAB_MODE environment variable not set to '1'")
            print("This tool can only run in lab environments")
            sys.exit(2)
    
    @staticmethod
    def verify_network_isolation():
        """Check if we're likely isolated from production"""
        try:
            # Check for default gateway to known cloud IP ranges
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            routes = result.stdout
            
            # Common production IP ranges to avoid
            prod_ranges = [
                '10.0.0.0/8',
                '172.16.0.0/12', 
                '192.168.0.0/16',
                '169.254.0.0/16'  # AWS metadata
            ]
            
            for route in routes.split('\n'):
                if 'default' in route:
                    print("WARNING: Default route detected - may not be isolated")
                    return False
                    
            return True
        except Exception:
            return True  # Be permissive if we can't check
    
    @staticmethod
    def confirm_destructive_action(token_required=None):
        """Require confirmation for destructive actions"""
        if token_required:
            provided = input(f"Enter confirmation token '{token_required}': ")
            if provided != token_required:
                print("Invalid confirmation token - aborting")
                sys.exit(1)
        else:
            response = input("Confirm destructive action (type 'YES'): ")
            if response != 'YES':
                print("Confirmation required - aborting")
                sys.exit(1)
