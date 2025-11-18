#!/usr/bin/env python3
"""
USB Implant Simulator - Educational Security Tool
Purpose: Emulate malicious USB device behaviors for security testing and research
Use: Security training, penetration testing, malware analysis in controlled environments
"""

import os
import sys
import time
import threading
import json
import random
import subprocess
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional
import logging
from pathlib import Path
import hashlib

# Platform-specific imports
try:
    import pyautogui
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    logging.warning("pyautogui not available - GUI automation disabled")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not available - system monitoring disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('usb_implant.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class USBImplantType(Enum):
    BADUSB = "badusb"
    HID_SPOOFING = "hid_spoofing"
    KEYBOARD_INJECTION = "keyboard_injection"
    STORAGE_BASED = "storage_based"
    NETWORK_GADGET = "network_gadget"
    COMPOSITE_ATTACK = "composite_attack"

@dataclass
class AttackProfile:
    name: str
    implant_type: USBImplantType
    description: str
    behaviors: List[str]
    persistence: bool
    stealth_level: int  # 1-10
    detection_difficulty: str  # low, medium, high

class USBImplantSimulator:
    def __init__(self, config_file="usb_implant_config.json"):
        self.config = self.load_config(config_file)
        self.attack_profiles = self.load_attack_profiles()
        self.is_running = False
        self.current_profile = None
        self.simulation_thread = None
        
        # Simulation state
        self.simulation_results = {
            "executed_attacks": [],
            "detected_events": [],
            "system_changes": [],
            "timeline": []
        }
        
        logger.info("USB Implant Simulator initialized - FOR EDUCATIONAL USE ONLY")
    
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "simulation": {
                "max_duration": 300,  # 5 minutes
                "safe_mode": True,
                "require_confirmation": True,
                "log_all_actions": True
            },
            "behavior": {
                "keyboard_delay": 0.1,
                "max_keystrokes": 100,
                "file_operations": True,
                "network_operations": False,
                "registry_operations": False
            },
            "safety": {
                "whitelisted_processes": ["notepad.exe", "calc.exe"],
                "blocked_commands": ["format", "del", "rm -rf", "shutdown"],
                "allowed_directories": ["/tmp", "C:\\Temp"]
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {config_file}")
                return {**default_config, **config}
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return default_config
    
    def load_attack_profiles(self) -> Dict[str, AttackProfile]:
        """Load predefined attack profiles"""
        profiles = {
            "basic_keylogger": AttackProfile(
                name="Basic Keylogger Simulation",
                implant_type=USBImplantType.KEYBOARD_INJECTION,
                description="Simulates basic keylogging behavior",
                behaviors=["open_notepad", "type_suspicious_text", "save_file"],
                persistence=False,
                stealth_level=3,
                detection_difficulty="low"
            ),
            "powershell_dropper": AttackProfile(
                name="PowerShell Payload Dropper",
                implant_type=USBImplantType.BADUSB,
                description="Simulates PowerShell-based payload delivery",
                behaviors=["open_powershell", "execute_encoded_command", "download_file"],
                persistence=True,
                stealth_level=6,
                detection_difficulty="medium"
            ),
            "reverse_shell": AttackProfile(
                name="Reverse Shell Simulation",
                implant_type=USBImplantType.NETWORK_GADGET,
                description="Simulates network-based reverse shell",
                behaviors=["check_network", "simulate_connection", "create_backdoor"],
                persistence=True,
                stealth_level=8,
                detection_difficulty="high"
            ),
            "data_exfiltration": AttackProfile(
                name="Data Exfiltration Simulation",
                implant_type=USBImplantType.STORAGE_BASED,
                description="Simulates data theft and exfiltration",
                behaviors=["search_sensitive_files", "compress_data", "simulate_upload"],
                persistence=False,
                stealth_level=7,
                detection_difficulty="medium"
            ),
            "composite_attack": AttackProfile(
                name="Composite Multi-Vector Attack",
                implant_type=USBImplantType.COMPOSITE_ATTACK,
                description="Combines multiple attack vectors",
                behaviors=["keyboard_injection", "file_operation", "network_call", "persistence_setup"],
                persistence=True,
                stealth_level=9,
                detection_difficulty="high"
            )
        }
        return profiles
    
    def list_profiles(self) -> None:
        """List available attack profiles"""
        print("Available USB Implant Attack Profiles:")
        print("=" * 60)
        for name, profile in self.attack_profiles.items():
            print(f"Name: {profile.name}")
            print(f"Type: {profile.implant_type.value}")
            print(f"Description: {profile.description}")
            print(f"Stealth: {profile.stealth_level}/10")
            print(f"Detection: {profile.detection_difficulty}")
            print(f"Behaviors: {', '.join(profile.behaviors)}")
            print("-" * 40)
    
    def simulate_keyboard_injection(self, profile: AttackProfile) -> None:
        """Simulate keyboard injection attacks"""
        logger.info("Starting keyboard injection simulation")
        
        behaviors = [
            self.simulate_opening_terminal,
            self.simulate_suspicious_typing,
            self.simulate_command_execution,
            self.simulate_file_creation
        ]
        
        for behavior in behaviors:
            if self.is_running:
                behavior()
                time.sleep(random.uniform(1, 3))
    
    def simulate_opening_terminal(self) -> None:
        """Simulate opening a terminal/command prompt"""
        if not GUI_AVAILABLE:
            logger.info("SIMULATION: Would open terminal/command prompt")
            return
        
        try:
            # Simulate Windows key + R to open Run dialog
            pyautogui.hotkey('win', 'r')
            time.sleep(0.5)
            
            # Type cmd and press Enter
            pyautogui.write('cmd')
            pyautogui.press('enter')
            time.sleep(1)
            
            self.record_event("opened_command_prompt", "User interaction simulation")
            
        except Exception as e:
            logger.error(f"Keyboard simulation failed: {e}")
    
    def simulate_suspicious_typing(self) -> None:
        """Simulate typing suspicious commands"""
        suspicious_commands = [
            "whoami",
            "ipconfig /all",
            "net user",
            "systeminfo",
            "dir C:\\Users"
        ]
        
        cmd = random.choice(suspicious_commands)
        logger.info(f"Simulating command typing: {cmd}")
        
        if GUI_AVAILABLE:
            try:
                pyautogui.write(cmd)
                time.sleep(0.5)
                pyautogui.press('enter')
                time.sleep(1)
            except Exception as e:
                logger.error(f"Command typing failed: {e}")
        
        self.record_event("typed_command", f"Command: {cmd}")
    
    def simulate_command_execution(self) -> None:
        """Simulate command execution behavior"""
        safe_commands = [
            "echo 'Security Test'",
            "hostname",
            "echo %USERNAME%",
            "ping 127.0.0.1 -n 2"
        ]
        
        cmd = random.choice(safe_commands)
        logger.info(f"Simulating command execution: {cmd}")
        
        try:
            if self.config['behavior']['file_operations']:
                # Execute in a safe manner
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                self.record_event("command_executed", f"Command: {cmd}, Output: {result.stdout[:100]}")
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
    
    def simulate_file_creation(self) -> None:
        """Simulate malicious file operations"""
        if not self.config['behavior']['file_operations']:
            return
        
        temp_dir = Path("/tmp") if os.name == 'posix' else Path("C:\\Temp")
        temp_dir.mkdir(exist_ok=True)
        
        # Create a harmless test file
        test_file = temp_dir / "usb_implant_test.txt"
        try:
            with open(test_file, 'w') as f:
                f.write("This is a test file created by USB Implant Simulator\n")
                f.write("Timestamp: " + time.ctime() + "\n")
                f.write("Purpose: Educational security testing\n")
            
            logger.info(f"Created test file: {test_file}")
            self.record_event("file_created", f"File: {test_file}")
            
            # Simulate file reading
            with open(test_file, 'r') as f:
                content = f.read()
                self.record_event("file_read", f"Read {len(content)} bytes from {test_file}")
            
            # Clean up
            test_file.unlink()
            self.record_event("file_deleted", f"File: {test_file}")
            
        except Exception as e:
            logger.error(f"File operation failed: {e}")
    
    def simulate_powershell_attack(self) -> None:
        """Simulate PowerShell-based attacks"""
        logger.info("Starting PowerShell attack simulation")
        
        # Safe PowerShell commands for simulation
        safe_ps_commands = [
            "Get-Process | Select-Object Name, CPU -First 5",
            "Get-Service | Where-Object Status -eq 'Running' | Select-Object Name -First 5",
            "Get-Date",
            "Write-Host 'Security Test Completed'"
        ]
        
        for cmd in safe_ps_commands:
            if not self.is_running:
                break
                
            try:
                if os.name == 'nt':  # Windows
                    full_cmd = f"powershell -Command \"{cmd}\""
                    result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=10)
                    logger.info(f"PowerShell command executed: {cmd}")
                    self.record_event("powershell_executed", f"Command: {cmd}")
                    
                time.sleep(2)
            except Exception as e:
                logger.error(f"PowerShell simulation failed: {e}")
    
    def simulate_network_behavior(self) -> None:
        """Simulate network-based malicious behavior"""
        if not self.config['behavior']['network_operations']:
            return
            
        logger.info("Starting network behavior simulation")
        
        network_actions = [
            self.simulate_dns_queries,
            self.simulate_http_requests,
            self.simulate_port_scanning
        ]
        
        for action in network_actions:
            if self.is_running:
                action()
                time.sleep(2)
    
    def simulate_dns_queries(self) -> None:
        """Simulate suspicious DNS queries"""
        domains = [
            "google.com",  # Benign domain
            "github.com",  # Benign domain  
            "microsoft.com"  # Benign domain
        ]
        
        for domain in domains:
            try:
                if os.name == 'posix':
                    subprocess.run(f"nslookup {domain}", shell=True, capture_output=True, timeout=5)
                else:
                    subprocess.run(f"nslookup {domain}", shell=True, capture_output=True, timeout=5)
                
                logger.info(f"Simulated DNS query for: {domain}")
                self.record_event("dns_query", f"Domain: {domain}")
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"DNS simulation failed: {e}")
    
    def simulate_http_requests(self) -> None:
        """Simulate HTTP requests (educational only)"""
        try:
            import requests
        except ImportError:
            logger.warning("requests module not available - HTTP simulation skipped")
            return
        
        # Only simulate requests to localhost or safe domains
        test_urls = [
            "http://localhost/",
            "http://127.0.0.1/",
            "https://httpbin.org/get"
        ]
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=10)
                logger.info(f"HTTP request to {url} - Status: {response.status_code}")
                self.record_event("http_request", f"URL: {url}, Status: {response.status_code}")
            except Exception as e:
                logger.error(f"HTTP request failed: {e}")
    
    def simulate_port_scanning(self) -> None:
        """Simulate port scanning behavior (educational only)"""
        # Only scan localhost for safety
        target = "127.0.0.1"
        ports = [80, 443, 22, 21]  # Common ports
        
        logger.info(f"Simulating port scan on {target}")
        
        for port in ports:
            try:
                if os.name == 'posix':
                    # Use netcat if available
                    result = subprocess.run(
                        f"nc -z -w 1 {target} {port}",
                        shell=True,
                        capture_output=True,
                        timeout=5
                    )
                else:
                    # Use telnet on Windows
                    result = subprocess.run(
                        f"telnet {target} {port}",
                        shell=True,
                        capture_output=True,
                        timeout=5,
                        input=b"\n"
                    )
                
                if result.returncode == 0:
                    logger.info(f"Port {port} appears open on {target}")
                    self.record_event("port_scan", f"Port {port} open on {target}")
                else:
                    logger.info(f"Port {port} appears closed on {target}")
                    
            except Exception as e:
                logger.error(f"Port scan simulation failed: {e}")
    
    def simulate_persistence_mechanism(self) -> None:
        """Simulate persistence mechanism setup"""
        logger.info("Simulating persistence mechanism")
        
        persistence_methods = [
            self.simulate_startup_folder,
            self.simulate_scheduled_task,
            self.simulate_registry_persistence
        ]
        
        for method in persistence_methods:
            if self.is_running:
                method()
                time.sleep(1)
    
    def simulate_startup_folder(self) -> None:
        """Simulate adding to startup folder"""
        logger.info("Simulating startup folder persistence")
        
        try:
            if os.name == 'nt':
                startup_path = Path(os.path.expanduser("~")) / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                startup_path.mkdir(parents=True, exist_ok=True)
                
                test_file = startup_path / "test_persistence.bat"
                with open(test_file, 'w') as f:
                    f.write("@echo off\necho Educational persistence test\n")
                
                self.record_event("startup_persistence", f"Created: {test_file}")
                
                # Clean up
                test_file.unlink()
                
        except Exception as e:
            logger.error(f"Startup persistence simulation failed: {e}")
    
    def simulate_scheduled_task(self) -> None:
        """Simulate scheduled task creation"""
        logger.info("Simulating scheduled task persistence")
        
        try:
            if os.name == 'nt':
                task_name = "USBSimulatorTest"
                cmd = f'schtasks /create /tn "{task_name}" /tr "echo test" /sc once /st 00:00 /f'
                result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
                
                if result.returncode == 0:
                    self.record_event("scheduled_task", f"Created task: {task_name}")
                    
                    # Delete the task
                    subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True, capture_output=True)
                    
        except Exception as e:
            logger.error(f"Scheduled task simulation failed: {e}")
    
    def simulate_registry_persistence(self) -> None:
        """Simulate registry persistence (Windows only)"""
        if os.name != 'nt' or not self.config['behavior']['registry_operations']:
            return
            
        logger.info("Simulating registry persistence")
        
        try:
            # Safe registry key for testing
            test_key = "HKEY_CURRENT_USER\\Software\\USBSimulatorTest"
            cmd = f'reg add "{test_key}" /v TestValue /t REG_SZ /d "Educational" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                self.record_event("registry_persistence", f"Created registry key: {test_key}")
                
                # Clean up
                subprocess.run(f'reg delete "{test_key}" /f', shell=True, capture_output=True)
                
        except Exception as e:
            logger.error(f"Registry persistence simulation failed: {e}")
    
    def monitor_system_changes(self) -> None:
        """Monitor system for changes during simulation"""
        if not PSUTIL_AVAILABLE:
            return
            
        logger.info("Starting system monitoring")
        
        initial_processes = set(p.info['name'] for p in psutil.process_iter(['name']))
        initial_connections = set(conn.laddr for conn in psutil.net_connections() if conn.laddr)
        
        while self.is_running:
            try:
                # Monitor new processes
                current_processes = set(p.info['name'] for p in psutil.process_iter(['name']))
                new_processes = current_processes - initial_processes
                
                if new_processes:
                    for process in new_processes:
                        self.record_event("new_process", f"Process: {process}")
                
                # Monitor network connections
                current_connections = set(conn.laddr for conn in psutil.net_connections() if conn.laddr)
                new_connections = current_connections - initial_connections
                
                if new_connections:
                    for conn in new_connections:
                        self.record_event("new_connection", f"Connection: {conn}")
                
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"System monitoring failed: {e}")
                break
    
    def record_event(self, event_type: str, details: str) -> None:
        """Record simulation events"""
        event = {
            "timestamp": time.time(),
            "type": event_type,
            "details": details
        }
        self.simulation_results["executed_attacks"].append(event)
        
        if self.config['simulation']['log_all_actions']:
            logger.info(f"Event: {event_type} - {details}")
    
    def start_simulation(self, profile_name: str) -> None:
        """Start the USB implant simulation"""
        if profile_name not in self.attack_profiles:
            logger.error(f"Unknown profile: {profile_name}")
            return
        
        if self.is_running:
            logger.error("Simulation already running")
            return
        
        profile = self.attack_profiles[profile_name]
        self.current_profile = profile
        
        logger.info(f"Starting USB implant simulation: {profile.name}")
        logger.info(f"Type: {profile.implant_type.value}")
        logger.info(f"Stealth level: {profile.stealth_level}/10")
        
        if self.config['simulation']['require_confirmation']:
            response = input("Continue with simulation? (y/N): ")
            if response.lower() != 'y':
                logger.info("Simulation cancelled by user")
                return
        
        self.is_running = True
        self.simulation_results = {
            "profile": profile.name,
            "start_time": time.time(),
            "executed_attacks": [],
            "detected_events": [],
            "system_changes": [],
            "timeline": []
        }
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_system_changes, daemon=True)
        monitor_thread.start()
        
        # Start simulation thread
        self.simulation_thread = threading.Thread(
            target=self._run_simulation, 
            args=(profile,),
            daemon=True
        )
        self.simulation_thread.start()
        
        logger.info("Simulation started successfully")
    
    def _run_simulation(self, profile: AttackProfile) -> None:
        """Internal method to run the simulation"""
        start_time = time.time()
        max_duration = self.config['simulation']['max_duration']
        
        try:
            # Execute based on implant type
            if profile.implant_type == USBImplantType.KEYBOARD_INJECTION:
                self.simulate_keyboard_injection(profile)
            elif profile.implant_type == USBImplantType.BADUSB:
                self.simulate_powershell_attack()
            elif profile.implant_type == USBImplantType.NETWORK_GADGET:
                self.simulate_network_behavior()
            elif profile.implant_type == USBImplantType.COMPOSITE_ATTACK:
                self.simulate_composite_attack(profile)
            
            # Add persistence if configured
            if profile.persistence:
                self.simulate_persistence_mechanism()
                
        except Exception as e:
            logger.error(f"Simulation error: {e}")
        finally:
            self.is_running = False
            duration = time.time() - start_time
            logger.info(f"Simulation completed in {duration:.2f} seconds")
    
    def simulate_composite_attack(self, profile: AttackProfile) -> None:
        """Simulate composite multi-vector attack"""
        logger.info("Starting composite attack simulation")
        
        attack_sequence = [
            (self.simulate_keyboard_injection, 5),
            (self.simulate_network_behavior, 10),
            (self.simulate_persistence_mechanism, 3)
        ]
        
        for attack_func, duration in attack_sequence:
            if not self.is_running:
                break
                
            start_time = time.time()
            while time.time() - start_time < duration and self.is_running:
                attack_func(profile)
                time.sleep(1)
    
    def stop_simulation(self) -> None:
        """Stop the running simulation"""
        if not self.is_running:
            logger.info("No simulation running")
            return
            
        self.is_running = False
        logger.info("Stopping simulation...")
        
        if self.simulation_thread:
            self.simulation_thread.join(timeout=10)
        
        self.generate_report()
    
    def generate_report(self) -> None:
        """Generate simulation report"""
        if not self.simulation_results["executed_attacks"]:
            logger.info("No simulation data to report")
            return
        
        report = {
            "simulation_profile": self.current_profile.name if self.current_profile else "Unknown",
            "total_events": len(self.simulation_results["executed_attacks"]),
            "events_by_type": {},
            "timeline": self.simulation_results["executed_attacks"],
            "summary": self._generate_summary()
        }
        
        # Count events by type
        for event in self.simulation_results["executed_attacks"]:
            event_type = event["type"]
            report["events_by_type"][event_type] = report["events_by_type"].get(event_type, 0) + 1
        
        # Save report to file
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = f"usb_implant_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Simulation report saved to: {report_file}")
        
        # Print summary
        self._print_report_summary(report)
    
    def _generate_summary(self) -> Dict:
        """Generate simulation summary"""
        total_events = len(self.simulation_results["executed_attacks"])
        
        event_types = {}
        for event in self.simulation_results["executed_attacks"]:
            event_type = event["type"]
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        return {
            "total_simulated_attacks": total_events,
            "attack_categories": event_types,
            "simulation_duration": self.simulation_results.get("duration", "Unknown"),
            "risk_assessment": self._assess_risk_level()
        }
    
    def _assess_risk_level(self) -> str:
        """Assess the risk level of simulated attacks"""
        if not self.current_profile:
            return "Unknown"
        
        stealth = self.current_profile.stealth_level
        detection = self.current_profile.detection_difficulty
        
        if stealth >= 8 and detection == "high":
            return "High"
        elif stealth >= 5 and detection == "medium":
            return "Medium"
        else:
            return "Low"
    
    def _print_report_summary(self, report: Dict) -> None:
        """Print report summary to console"""
        print("\n" + "="*60)
        print("USB IMPLANT SIMULATION REPORT")
        print("="*60)
        print(f"Profile: {report['simulation_profile']}")
        print(f"Total Events: {report['total_events']}")
        print("\nEvent Breakdown:")
        for event_type, count in report['events_by_type'].items():
            print(f"  {event_type}: {count}")
        print(f"\nRisk Level: {report['summary']['risk_assessment']}")
        print("="*60)

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='USB Implant Simulator - Educational Tool')
    parser.add_argument('--list-profiles', action='store_true', help='List available attack profiles')
    parser.add_argument('--simulate', help='Start simulation with specified profile')
    parser.add_argument('--stop', action='store_true', help='Stop current simulation')
    parser.add_argument('--report', action='store_true', help='Generate report from last simulation')
    
    args = parser.parse_args()
    
    simulator = USBImplantSimulator()
    
    try:
        if args.list_profiles:
            simulator.list_profiles()
        elif args.simulate:
            simulator.start_simulation(args.simulate)
            
            # Wait for simulation to complete or be stopped
            try:
                while simulator.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                simulator.stop_simulation()
                
        elif args.stop:
            simulator.stop_simulation()
        elif args.report:
            simulator.generate_report()
        else:
            print("USB Implant Simulator - FOR EDUCATIONAL USE ONLY")
            print("Use --help for available commands")
            
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
