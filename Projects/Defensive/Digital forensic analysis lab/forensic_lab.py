#!/usr/bin/env python3
"""
Digital Forensic Analysis Lab - Python Implementation
Memory, disk, and artifact analysis capabilities
"""

import os
import sys
import struct
import hashlib
import json
import sqlite3
import argparse
import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import mmap
import pickle

class MemoryAnalyzer:
    """Memory forensic analysis capabilities"""
    
    def __init__(self, memory_dump_path: str):
        self.memory_dump_path = memory_dump_path
        self.processes = []
        self.network_connections = []
        self.loaded_modules = []
        
    def analyze_memory_dump(self) -> Dict[str, Any]:
        """Analyze memory dump for forensic artifacts"""
        print(f"[*] Analyzing memory dump: {self.memory_dump_path}")
        
        analysis_results = {
            'file_info': self._get_file_info(),
            'processes': self._extract_processes(),
            'network_connections': self._extract_network_connections(),
            'loaded_modules': self._extract_loaded_modules(),
            'strings': self._extract_strings(),
            'malware_indicators': self._scan_malware_indicators()
        }
        
        return analysis_results
    
    def _get_file_info(self) -> Dict[str, Any]:
        """Get memory dump file information"""
        file_stat = os.stat(self.memory_dump_path)
        return {
            'size': file_stat.st_size,
            'created': datetime.datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            'modified': datetime.datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            'md5': self._calculate_file_hash(self.memory_dump_path)
        }
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def _extract_processes(self) -> List[Dict[str, Any]]:
        """Extract process information from memory (simulated)"""
        # In real implementation, this would parse memory structures
        simulated_processes = [
            {
                'pid': 4,
                'name': 'System',
                'parent_pid': 0,
                'path': 'C:\\Windows\\System32\\ntoskrnl.exe',
                'command_line': '',
                'start_time': '2024-01-15T08:00:00'
            },
            {
                'pid': 264,
                'name': 'csrss.exe',
                'parent_pid': 4,
                'path': 'C:\\Windows\\System32\\csrss.exe',
                'command_line': 'csrss.exe ObjectDirectory=\\Windows',
                'start_time': '2024-01-15T08:00:01'
            },
            {
                'pid': 1884,
                'name': 'notepad.exe',
                'parent_pid': 264,
                'path': 'C:\\Windows\\System32\\notepad.exe',
                'command_line': 'notepad.exe C:\\secret.txt',
                'start_time': '2024-01-15T10:30:15'
            },
            {
                'pid': 1922,
                'name': 'suspicious.exe',
                'parent_pid': 1884,
                'path': 'C:\\Temp\\suspicious.exe',
                'command_line': 'suspicious.exe -stealth',
                'start_time': '2024-01-15T10:31:22'
            }
        ]
        return simulated_processes
    
    def _extract_network_connections(self) -> List[Dict[str, Any]]:
        """Extract network connection information"""
        simulated_connections = [
            {
                'protocol': 'TCP',
                'local_address': '192.168.1.100',
                'local_port': 49215,
                'remote_address': '45.33.32.156',
                'remote_port': 443,
                'state': 'ESTABLISHED',
                'pid': 1922
            },
            {
                'protocol': 'UDP',
                'local_address': '192.168.1.100',
                'local_port': 53,
                'remote_address': '8.8.8.8',
                'remote_port': 53,
                'state': 'LISTENING',
                'pid': 984
            }
        ]
        return simulated_connections
    
    def _extract_loaded_modules(self) -> List[Dict[str, Any]]:
        """Extract loaded DLLs and modules"""
        simulated_modules = [
            {
                'name': 'kernel32.dll',
                'path': 'C:\\Windows\\System32\\kernel32.dll',
                'base_address': '0x7ffe0000',
                'size': '2.5MB',
                'pid': 1922
            },
            {
                'name': 'malicious.dll',
                'path': 'C:\\Temp\\malicious.dll',
                'base_address': '0x10000000',
                'size': '256KB',
                'pid': 1922
            }
        ]
        return simulated_modules
    
    def _extract_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract ASCII strings from memory dump"""
        strings_found = []
        try:
            with open(self.memory_dump_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    current_string = b''
                    offset = 0
                    
                    for byte in mm:
                        if 32 <= byte <= 126:  # Printable ASCII
                            current_string += bytes([byte])
                        else:
                            if len(current_string) >= min_length:
                                strings_found.append({
                                    'offset': hex(offset - len(current_string)),
                                    'string': current_string.decode('ascii', errors='ignore'),
                                    'length': len(current_string)
                                })
                            current_string = b''
                        offset += 1
        except Exception as e:
            print(f"[-] Error extracting strings: {e}")
        
        return strings_found[:1000]  # Limit output
    
    def _scan_malware_indicators(self) -> List[Dict[str, Any]]:
        """Scan for malware indicators"""
        indicators = [
            {'type': 'Process', 'indicator': 'suspicious.exe', 'confidence': 'High'},
            {'type': 'Module', 'indicator': 'malicious.dll', 'confidence': 'High'},
            {'type': 'IP', 'indicator': '45.33.32.156', 'confidence': 'Medium'},
            {'type': 'String', 'indicator': 'MZ header in memory', 'confidence': 'Low'}
        ]
        return indicators

class DiskAnalyzer:
    """Disk image forensic analysis"""
    
    def __init__(self, disk_image_path: str):
        self.disk_image_path = disk_image_path
        
    def analyze_disk_image(self) -> Dict[str, Any]:
        """Analyze disk image for forensic artifacts"""
        print(f"[*] Analyzing disk image: {self.disk_image_path}")
        
        return {
            'file_system': self._analyze_file_system(),
            'deleted_files': self._find_deleted_files(),
            'timeline': self._create_timeline(),
            'registry_analysis': self._analyze_registry(),
            'browser_artifacts': self._extract_browser_artifacts(),
            'prefetch_files': self._analyze_prefetch()
        }
    
    def _analyze_file_system(self) -> Dict[str, Any]:
        """Analyze file system structure"""
        return {
            'type': 'NTFS',
            'cluster_size': 4096,
            'total_size': '500GB',
            'used_space': '350GB',
            'free_space': '150GB',
            'mft_location': '0x0C0000'
        }
    
    def _find_deleted_files(self) -> List[Dict[str, Any]]:
        """Find and analyze deleted files"""
        deleted_files = [
            {
                'filename': 'secret_document.pdf',
                'original_path': 'C:\\Users\\John\\Documents\\',
                'deleted_time': '2024-01-15T10:35:00',
                'recoverable': True,
                'size': '2.5MB'
            },
            {
                'filename': 'malware.exe',
                'original_path': 'C:\\Temp\\',
                'deleted_time': '2024-01-15T10:32:00',
                'recoverable': False,
                'size': '1.2MB'
            }
        ]
        return deleted_files
    
    def _create_timeline(self) -> List[Dict[str, Any]]:
        """Create forensic timeline"""
        timeline = [
            {
                'timestamp': '2024-01-15T08:00:00',
                'event': 'System Boot',
                'source': 'System',
                'artifact': 'Event Log'
            },
            {
                'timestamp': '2024-01-15T10:30:15',
                'event': 'Notepad started',
                'source': 'Process',
                'artifact': 'Prefetch'
            },
            {
                'timestamp': '2024-01-15T10:31:22',
                'event': 'Suspicious process started',
                'source': 'Process',
                'artifact': 'Memory'
            },
            {
                'timestamp': '2024-01-15T10:35:00',
                'event': 'File deleted',
                'source': 'File System',
                'artifact': 'MFT'
            }
        ]
        return timeline
    
    def _analyze_registry(self) -> Dict[str, Any]:
        """Analyze Windows registry artifacts"""
        return {
            'user_activity': [
                {'key': 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'value': 'malware.exe'},
                {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'value': 'Shell=explorer.exe,malware.exe'}
            ],
            'persistence': [
                {'type': 'Run Key', 'entry': 'malware.exe', 'path': 'C:\\Temp\\malware.exe'}
            ],
            'network_settings': [
                {'key': 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters', 'value': 'NameServer=8.8.8.8'}
            ]
        }
    
    def _extract_browser_artifacts(self) -> Dict[str, Any]:
        """Extract web browser forensic artifacts"""
        return {
            'chrome_history': [
                {'url': 'https://github.com/malware-samples', 'visit_count': 5, 'last_visit': '2024-01-15T10:25:00'},
                {'url': 'https://192.168.1.50:8443/admin', 'visit_count': 3, 'last_visit': '2024-01-15T10:28:00'}
            ],
            'downloads': [
                {'filename': 'suspicious_tool.zip', 'url': 'http://malicious-site.com/tool.zip', 'download_time': '2024-01-15T10:20:00'}
            ],
            'cookies': [
                {'domain': '.malicious-site.com', 'name': 'session_id', 'value': 'encrypted_data'}
            ]
        }
    
    def _analyze_prefetch(self) -> List[Dict[str, Any]]:
        """Analyze Windows prefetch files"""
        return [
            {
                'filename': 'NOTEPAD.EXE-123456.pf',
                'original_path': 'C:\\Windows\\System32\\notepad.exe',
                'run_count': 15,
                'last_run': '2024-01-15T10:30:15'
            },
            {
                'filename': 'SUSPICIOUS.EXE-789012.pf',
                'original_path': 'C:\\Temp\\suspicious.exe',
                'run_count': 1,
                'last_run': '2024-01-15T10:31:22'
            }
        ]

class ArtifactExtractor:
    """Extract specific forensic artifacts"""
    
    def __init__(self, evidence_path: str):
        self.evidence_path = evidence_path
    
    def extract_all_artifacts(self) -> Dict[str, Any]:
        """Extract comprehensive forensic artifacts"""
        artifacts = {
            'system_info': self._extract_system_info(),
            'user_activity': self._extract_user_activity(),
            'network_artifacts': self._extract_network_artifacts(),
            'application_artifacts': self._extract_application_artifacts(),
            'security_artifacts': self._extract_security_artifacts()
        }
        return artifacts
    
    def _extract_system_info(self) -> Dict[str, Any]:
        """Extract system information artifacts"""
        return {
            'hostname': 'DESKTOP-ABC123',
            'os_version': 'Windows 10 Pro 22H2',
            'install_date': '2023-06-15',
            'timezone': 'Eastern Standard Time',
            'users': ['John', 'Administrator', 'Guest']
        }
    
    def _extract_user_activity(self) -> Dict[str, Any]:
        """Extract user activity artifacts"""
        return {
            'recent_documents': [
                'C:\\Users\\John\\Documents\\project.docx',
                'C:\\Users\\John\\Downloads\\invoice.pdf'
            ],
            'desktop_files': ['secret.txt', 'malware.lnk'],
            'run_commands': ['cmd.exe /c whoami', 'powershell -ep bypass -c IEX'],
            'clipboard_data': 'Sensitive information copied'
        }
    
    def _extract_network_artifacts(self) -> Dict[str, Any]:
        """Extract network-related artifacts"""
        return {
            'arp_cache': [
                {'ip': '192.168.1.1', 'mac': '00:11:22:33:44:55', 'interface': 'Ethernet'}
            ],
            'dns_cache': [
                {'hostname': 'malicious-domain.com', 'ip': '45.33.32.156', 'ttl': 300}
            ],
            'connection_history': [
                {'protocol': 'TCP', 'local_port': 49215, 'remote_ip': '45.33.32.156', 'remote_port': 443}
            ]
        }
    
    def _extract_application_artifacts(self) -> Dict[str, Any]:
        """Extract application-specific artifacts"""
        return {
            'office_documents': [
                {'filename': 'sensitive.docx', 'path': 'C:\\Users\\John\\Documents\\', 'last_accessed': '2024-01-15T10:25:00'}
            ],
            'email_clients': [
                {'client': 'Outlook', 'profile': 'John', 'last_sync': '2024-01-15T09:30:00'}
            ],
            'instant_messaging': [
                {'application': 'Telegram', 'username': 'john_doe', 'last_activity': '2024-01-15T10:20:00'}
            ]
        }
    
    def _extract_security_artifacts(self) -> Dict[str, Any]:
        """Extract security-related artifacts"""
        return {
            'antivirus_logs': [
                {'timestamp': '2024-01-15T10:31:25', 'event': 'Threat detected', 'file': 'C:\\Temp\\suspicious.exe'}
            ],
            'firewall_rules': [
                {'name': 'Allow suspicious', 'direction': 'Outbound', 'protocol': 'TCP', 'port': '443'}
            ],
            'event_logs': [
                {'log': 'Security', 'event_id': 4624, 'description': 'Successful logon', 'timestamp': '2024-01-15T08:05:00'}
            ]
        }

class ForensicReportGenerator:
    """Generate comprehensive forensic reports"""
    
    def __init__(self):
        self.report_data = {}
    
    def generate_report(self, memory_analysis: Dict, disk_analysis: Dict, artifacts: Dict) -> str:
        """Generate comprehensive forensic report"""
        report = {
            'metadata': {
                'generated': datetime.datetime.now().isoformat(),
                'analyst': 'Forensic Investigator',
                'case_id': 'CASE-2024-001'
            },
            'executive_summary': self._generate_executive_summary(memory_analysis, disk_analysis),
            'detailed_findings': {
                'memory_analysis': memory_analysis,
                'disk_analysis': disk_analysis,
                'artifacts': artifacts
            },
            'timeline_analysis': self._generate_timeline_analysis(disk_analysis.get('timeline', [])),
            'malware_analysis': self._generate_malware_analysis(memory_analysis.get('malware_indicators', [])),
            'recommendations': self._generate_recommendations()
        }
        
        return json.dumps(report, indent=2)
    
    def _generate_executive_summary(self, memory: Dict, disk: Dict) -> Dict[str, Any]:
        """Generate executive summary"""
        suspicious_processes = [p for p in memory.get('processes', []) if 'suspicious' in p['name'].lower()]
        malware_indicators = memory.get('malware_indicators', [])
        
        return {
            'findings_summary': f"Found {len(suspicious_processes)} suspicious processes and {len(malware_indicators)} malware indicators",
            'key_events': [
                'Suspicious process execution detected',
                'Network connections to known malicious IPs',
                'Evidence of data exfiltration attempts'
            ],
            'confidence_level': 'High',
            'impact_assessment': 'Medium to High'
        }
    
    def _generate_timeline_analysis(self, timeline: List[Dict]) -> Dict[str, Any]:
        """Generate timeline analysis"""
        return {
            'total_events': len(timeline),
            'key_events': [event for event in timeline if 'suspicious' in event['event'].lower()],
            'attack_chain': self._reconstruct_attack_chain(timeline)
        }
    
    def _reconstruct_attack_chain(self, timeline: List[Dict]) -> List[str]:
        """Reconstruct attack chain from timeline"""
        attack_steps = []
        for event in timeline:
            if 'suspicious' in event['event'].lower() or 'malware' in event['event'].lower():
                attack_steps.append(f"{event['timestamp']}: {event['event']}")
        return attack_steps
    
    def _generate_malware_analysis(self, indicators: List[Dict]) -> Dict[str, Any]:
        """Generate malware analysis section"""
        high_confidence = [i for i in indicators if i['confidence'] == 'High']
        medium_confidence = [i for i in indicators if i['confidence'] == 'Medium']
        
        return {
            'total_indicators': len(indicators),
            'high_confidence_indicators': high_confidence,
            'medium_confidence_indicators': medium_confidence,
            'attribution_hints': ['Possible APT group based on TTPs'],
            'recommended_actions': ['Isolate affected systems', 'Conduct deeper memory analysis']
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations"""
        return [
            'Implement stronger endpoint detection and response',
            'Review and update firewall rules',
            'Conduct user awareness training',
            'Implement application whitelisting',
            'Enhance logging and monitoring capabilities'
        ]

def main():
    parser = argparse.ArgumentParser(description='Digital Forensic Analysis Lab')
    subparsers = parser.add_subparsers(dest='command', help='Analysis command')
    
    # Memory analysis command
    memory_parser = subparsers.add_parser('memory', help='Analyze memory dump')
    memory_parser.add_argument('-i', '--input', required=True, help='Memory dump file')
    memory_parser.add_argument('-o', '--output', help='Output file for results')
    
    # Disk analysis command
    disk_parser = subparsers.add_parser('disk', help='Analyze disk image')
    disk_parser.add_argument('-i', '--input', required=True, help='Disk image file')
    disk_parser.add_argument('-o', '--output', help='Output file for results')
    
    # Artifact extraction command
    artifact_parser = subparsers.add_parser('artifacts', help='Extract forensic artifacts')
    artifact_parser.add_argument('-i', '--input', required=True, help='Evidence directory')
    artifact_parser.add_argument('-o', '--output', help='Output file for results')
    
    # Full analysis command
    full_parser = subparsers.add_parser('full', help='Complete forensic analysis')
    full_parser.add_argument('-m', '--memory', help='Memory dump file')
    full_parser.add_argument('-d', '--disk', help='Disk image file')
    full_parser.add_argument('-a', '--artifacts', help='Evidence directory')
    full_parser.add_argument('-o', '--output', required=True, help='Output report file')
    
    args = parser.parse_args()
    
    if args.command == 'memory':
        analyzer = MemoryAnalyzer(args.input)
        results = analyzer.analyze_memory_dump()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Memory analysis saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
    
    elif args.command == 'disk':
        analyzer = DiskAnalyzer(args.input)
        results = analyzer.analyze_disk_image()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Disk analysis saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
    
    elif args.command == 'artifacts':
        extractor = ArtifactExtractor(args.input)
        results = extractor.extract_all_artifacts()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Artifacts saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
    
    elif args.command == 'full':
        # Perform complete analysis
        memory_results = {}
        disk_results = {}
        artifact_results = {}
        
        if args.memory:
            memory_analyzer = MemoryAnalyzer(args.memory)
            memory_results = memory_analyzer.analyze_memory_dump()
        
        if args.disk:
            disk_analyzer = DiskAnalyzer(args.disk)
            disk_results = disk_analyzer.analyze_disk_image()
        
        if args.artifacts:
            artifact_extractor = ArtifactExtractor(args.artifacts)
            artifact_results = artifact_extractor.extract_all_artifacts()
        
        # Generate comprehensive report
        report_generator = ForensicReportGenerator()
        report = report_generator.generate_report(memory_results, disk_results, artifact_results)
        
        with open(args.output, 'w') as f:
            f.write(report)
        
        print(f"[+] Comprehensive forensic report saved to {args.output}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
