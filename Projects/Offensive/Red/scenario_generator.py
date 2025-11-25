#!/usr/bin/env python3
"""
Red/Blue Exercise Scenarios Generator - Python Implementation
Creates realistic cyber exercise scenarios for training
"""

import random
import json
import yaml
import argparse
import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import hashlib

@dataclass
class AttackTechnique:
    id: str
    name: str
    description: str
    difficulty: str  # Low, Medium, High
    mitre_attack_id: str
    detection_difficulty: str  # Easy, Medium, Hard
    ioc_indicators: List[str]
    countermeasures: List[str]

@dataclass
class ScenarioObjective:
    name: str
    description: str
    points: int
    category: str  # InitialAccess, Execution, Persistence, etc.

@dataclass
class BlueTeamAction:
    name: str
    description: str
    effectiveness: str  # High, Medium, Low
    tools: List[str]
    time_required: str  # Minutes, Hours, Days

@dataclass
class ExerciseScenario:
    name: str
    description: str
    difficulty: str
    duration: str
    red_team_objectives: List[ScenarioObjective]
    blue_team_objectives: List[ScenarioObjective]
    attack_techniques: List[AttackTechnique]
    blue_team_actions: List[BlueTeamAction]
    infrastructure: Dict[str, Any]
    scoring_rubric: Dict[str, Any]

class ScenarioGenerator:
    def __init__(self):
        self.attack_techniques = self._load_attack_techniques()
        self.infrastructure_templates = self._load_infrastructure_templates()
        self.scenario_templates = self._load_scenario_templates()
        
    def _load_attack_techniques(self) -> List[AttackTechnique]:
        """Load predefined attack techniques"""
        return [
            AttackTechnique(
                id="T1566.001",
                name="Phishing - Spearphishing Attachment",
                description="Send targeted emails with malicious attachments",
                difficulty="Medium",
                mitre_attack_id="T1566.001",
                detection_difficulty="Medium",
                ioc_indicators=[
                    "Unusual email attachments",
                    "Suspicious sender domains", 
                    "Macro-enabled documents",
                    "Unusual process spawning from email clients"
                ],
                countermeasures=[
                    "Email filtering for executable attachments",
                    "User awareness training",
                    "Endpoint detection for macro execution",
                    "Network monitoring for C2 communications"
                ]
            ),
            AttackTechnique(
                id="T1059.003",
                name="Command and Scripting Interpreter - Windows Command Shell",
                description="Use cmd.exe for command execution",
                difficulty="Low",
                mitre_attack_id="T1059.003",
                detection_difficulty="Easy",
                ioc_indicators=[
                    "Suspicious command-line arguments",
                    "Unusual parent-child process relationships",
                    "Commands from unusual locations",
                    "Base64 encoded commands"
                ],
                countermeasures=[
                    "Process monitoring and logging",
                    "Application whitelisting",
                    "Command-line argument auditing",
                    "EDR solutions"
                ]
            ),
            AttackTechnique(
                id="T1134",
                name="Access Token Manipulation",
                description="Manipulate access tokens to escalate privileges",
                difficulty="High",
                mitre_attack_id="T1134",
                detection_difficulty="Hard",
                ioc_indicators=[
                    "Token manipulation API calls",
                    "Unusual process integrity levels",
                    "Privilege escalation attempts",
                    "Abnormal token assignments"
                ],
                countermeasures=[
                    "Privileged account management",
                    "Token filtering",
                    "Process integrity monitoring",
                    "Least privilege principle"
                ]
            ),
            AttackTechnique(
                id="T1027",
                name="Obfuscated Files or Information",
                description="Use obfuscation to hide malicious code",
                difficulty="Medium",
                mitre_attack_id="T1027",
                detection_difficulty="Hard",
                ioc_indicators=[
                    "Encrypted or encoded network traffic",
                    "Suspicious file entropy",
                    "Obfuscated PowerShell scripts",
                    "Packed executables"
                ],
                countermeasures=[
                    "Network traffic analysis",
                    "File entropy analysis",
                    "Behavioral detection",
                    "Memory analysis"
                ]
            )
        ]
    
    def _load_infrastructure_templates(self) -> Dict[str, Any]:
        """Load infrastructure templates for different scenarios"""
        return {
            "corporate_network": {
                "description": "Standard corporate network environment",
                "assets": [
                    {"type": "Domain Controller", "count": 2, "os": "Windows Server 2019"},
                    {"type": "File Server", "count": 1, "os": "Windows Server 2019"},
                    {"type": "Web Server", "count": 2, "os": "Linux Ubuntu"},
                    {"type": "Workstation", "count": 20, "os": "Windows 10"},
                    {"type": "Network Firewall", "count": 1},
                    {"type": "IDS/IPS", "count": 1},
                    {"type": "SIEM", "count": 1}
                ],
                "users": 50,
                "departments": ["HR", "Finance", "IT", "Marketing", "Operations"]
            },
            "industrial_control": {
                "description": "Industrial Control System (ICS) environment",
                "assets": [
                    {"type": "HMI", "count": 3, "os": "Windows 10"},
                    {"type": "PLC", "count": 10},
                    {"type": "Engineering Workstation", "count": 5, "os": "Windows 10"},
                    {"type": "Historian", "count": 1, "os": "Windows Server 2019"},
                    {"type": "ICS Firewall", "count": 2},
                    {"type": "SCADA Server", "count": 2, "os": "Windows Server 2019"}
                ],
                "users": 25,
                "departments": ["Operations", "Engineering", "Maintenance"]
            },
            "cloud_environment": {
                "description": "Cloud-native environment",
                "assets": [
                    {"type": "EC2 Instances", "count": 10, "os": "Linux/Windows"},
                    {"type": "S3 Buckets", "count": 5},
                    {"type": "RDS Databases", "count": 2},
                    {"type": "Load Balancer", "count": 1},
                    {"type": "CloudTrail", "count": 1},
                    {"type": "CloudWatch", "count": 1},
                    {"type": "WAF", "count": 1}
                ],
                "users": 100,
                "departments": ["Development", "Operations", "Security"]
            }
        }
    
    def _load_scenario_templates(self) -> Dict[str, Any]:
        """Load scenario templates"""
        return {
            "apt_simulation": {
                "name": "Advanced Persistent Threat Simulation",
                "description": "Simulate sophisticated nation-state actor",
                "difficulty": "High",
                "duration": "2 weeks",
                "red_focus": ["Persistence", "Lateral Movement", "Data Exfiltration"],
                "blue_focus": ["Threat Hunting", "Incident Response", "Forensics"]
            },
            "ransomware_attack": {
                "name": "Ransomware Attack Scenario",
                "description": "Simulate ransomware deployment and impact",
                "difficulty": "Medium", 
                "duration": "3 days",
                "red_focus": ["Initial Access", "Execution", "Impact"],
                "blue_focus": ["Containment", "Recovery", "Business Continuity"]
            },
            "insider_threat": {
                "name": "Insider Threat Scenario", 
                "description": "Simulate malicious insider activities",
                "difficulty": "Medium",
                "duration": "1 week",
                "red_focus": ["Privilege Abuse", "Data Theft", "Sabotage"],
                "blue_focus": ["User Monitoring", "DLP", "Behavioral Analysis"]
            },
            "supply_chain": {
                "name": "Supply Chain Compromise",
                "description": "Simulate attack through third-party vendor",
                "difficulty": "High",
                "duration": "10 days", 
                "red_focus": ["Initial Access", "Trust Abuse", "Lateral Movement"],
                "blue_focus": ["Vendor Risk Management", "Network Segmentation", "Monitoring"]
            }
        }
    
    def generate_scenario(self, scenario_type: str, infrastructure: str, difficulty: str = "Medium") -> ExerciseScenario:
        """Generate a complete exercise scenario"""
        template = self.scenario_templates.get(scenario_type, self.scenario_templates["apt_simulation"])
        infra = self.infrastructure_templates.get(infrastructure, self.infrastructure_templates["corporate_network"])
        
        # Select appropriate attack techniques based on difficulty
        techniques = self._select_techniques(difficulty)
        
        # Generate objectives
        red_objectives = self._generate_red_team_objectives(template["red_focus"])
        blue_objectives = self._generate_blue_team_objectives(template["blue_focus"])
        
        # Generate blue team actions
        blue_actions = self._generate_blue_team_actions(techniques)
        
        # Generate scoring rubric
        scoring = self._generate_scoring_rubric(red_objectives, blue_objectives)
        
        return ExerciseScenario(
            name=f"{template['name']} - {infra['description']}",
            description=template["description"],
            difficulty=difficulty,
            duration=template["duration"],
            red_team_objectives=red_objectives,
            blue_team_objectives=blue_objectives,
            attack_techniques=techniques,
            blue_team_actions=blue_actions,
            infrastructure=infra,
            scoring_rubric=scoring
        )
    
    def _select_techniques(self, difficulty: str) -> List[AttackTechnique]:
        """Select attack techniques based on difficulty"""
        difficulty_map = {
            "Low": ["Low"],
            "Medium": ["Low", "Medium"],
            "High": ["Low", "Medium", "High"]
        }
        
        allowed_difficulties = difficulty_map.get(difficulty, ["Medium"])
        return [tech for tech in self.attack_techniques if tech.difficulty in allowed_difficulties]
    
    def _generate_red_team_objectives(self, focus_areas: List[str]) -> List[ScenarioObjective]:
        """Generate red team objectives"""
        objectives = []
        
        objective_templates = {
            "InitialAccess": [
                ("Gain Initial Foothold", "Establish initial access to the target environment", 25),
                ("Phishing Campaign", "Successfully deliver phishing payload to multiple users", 30)
            ],
            "Persistence": [
                ("Establish Persistence", "Create at least 2 persistence mechanisms", 35),
                ("Backdoor Installation", "Install backdoor on critical system", 40)
            ],
            "LateralMovement": [
                ("Domain Compromise", "Compromise domain administrator account", 50),
                ("Network Enumeration", "Map the entire network infrastructure", 25)
            ],
            "DataExfiltration": [
                ("Data Collection", "Identify and collect sensitive data", 30),
                ("Exfiltration", "Successfully exfiltrate data without detection", 45)
            ],
            "Execution": [
                ("Code Execution", "Execute arbitrary code on multiple systems", 20),
                ("Privilege Escalation", "Escalate privileges on critical system", 35)
            ]
        }
        
        for area in focus_areas:
            if area in objective_templates:
                for name, desc, points in objective_templates[area]:
                    objectives.append(ScenarioObjective(
                        name=name,
                        description=desc,
                        points=points,
                        category=area
                    ))
        
        return objectives
    
    def _generate_blue_team_objectives(self, focus_areas: List[str]) -> List[ScenarioObjective]:
        """Generate blue team objectives"""
        objectives = []
        
        objective_templates = {
            "Threat Hunting": [
                ("IOC Identification", "Identify at least 5 IOCs from attack", 30),
                ("Attack Timeline", "Reconstruct complete attack timeline", 40)
            ],
            "Incident Response": [
                ("Containment", "Contain the incident within 2 hours", 35),
                ("Eradication", "Remove all attacker persistence mechanisms", 45)
            ],
            "Forensics": [
                ("Evidence Collection", "Collect forensic evidence from 3 systems", 25),
                ("Root Cause Analysis", "Determine root cause of compromise", 30)
            ],
            "Monitoring": [
                ("Alert Tuning", "Create new detection rules based on attack", 20),
                ("False Positive Reduction", "Reduce false positives by 50%", 25)
            ]
        }
        
        for area in focus_areas:
            if area in objective_templates:
                for name, desc, points in objective_templates[area]:
                    objectives.append(ScenarioObjective(
                        name=name,
                        description=desc,
                        points=points,
                        category=area
                    ))
        
        return objectives
    
    def _generate_blue_team_actions(self, techniques: List[AttackTechnique]) -> List[BlueTeamAction]:
        """Generate recommended blue team actions"""
        actions = []
        
        for tech in techniques:
            for countermeasure in tech.countermeasures:
                actions.append(BlueTeamAction(
                    name=f"Defend against {tech.name}",
                    description=f"Implement {countermeasure}",
                    effectiveness="High",
                    tools=["SIEM", "EDR", "Network Monitoring"],
                    time_required="1-2 hours"
                ))
        
        # Add general blue team actions
        general_actions = [
            BlueTeamAction(
                name="Network Traffic Analysis",
                description="Analyze network flows for suspicious patterns",
                effectiveness="Medium",
                tools=["Wireshark", "Zeek", "Suricata"],
                time_required="2-4 hours"
            ),
            BlueTeamAction(
                name="Endpoint Investigation",
                description="Conduct deep dive on compromised endpoints",
                effectiveness="High", 
                tools=["EDR", "Volatility", "Audit Logs"],
                time_required="3-5 hours"
            ),
            BlueTeamAction(
                name="User Awareness Assessment",
                description="Evaluate user susceptibility to social engineering",
                effectiveness="Medium",
                tools=["Phishing Simulation", "Training Platforms"],
                time_required="1 day"
            )
        ]
        
        actions.extend(general_actions)
        return actions
    
    def _generate_scoring_rubric(self, red_objs: List[ScenarioObjective], blue_objs: List[ScenarioObjective]) -> Dict[str, Any]:
        """Generate scoring rubric for the exercise"""
        return {
            "red_team_scoring": {
                "objective_completion": {
                    "description": "Points for completed objectives",
                    "max_points": sum(obj.points for obj in red_objs)
                },
                "stealth": {
                    "description": "Points for avoiding detection",
                    "max_points": 50
                },
                "time_efficiency": {
                    "description": "Points for completing objectives quickly",
                    "max_points": 30
                }
            },
            "blue_team_scoring": {
                "objective_completion": {
                    "description": "Points for completed objectives", 
                    "max_points": sum(obj.points for obj in blue_objs)
                },
                "detection_time": {
                    "description": "Points for quick detection",
                    "max_points": 40
                },
                "containment_effectiveness": {
                    "description": "Points for effective containment",
                    "max_points": 35
                },
                "documentation": {
                    "description": "Points for thorough documentation",
                    "max_points": 25
                }
            },
            "win_conditions": {
                "red_team_win": "Score 70% of total possible points",
                "blue_team_win": "Score 70% of total possible points and contain attack within 4 hours",
                "draw": "Both teams score between 50-70% of possible points"
            }
        }
    
    def generate_inject(self, scenario: ExerciseScenario, inject_type: str) -> Dict[str, Any]:
        """Generate exercise injects (events during the exercise)"""
        inject_templates = {
            "phishing_email": {
                "type": "Phishing Email",
                "description": "Simulated phishing email sent to employees",
                "difficulty": "Medium",
                "iocs": ["Suspicious sender", "Malicious attachment", "Urgent language"],
                "response_actions": ["Analyze email headers", "Check attachment hashes", "Block sender"]
            },
            "malware_detection": {
                "type": "Malware Alert",
                "description": "Endpoint detection alert for suspicious process",
                "difficulty": "High", 
                "iocs": ["Unknown process", "Suspicious network connections", "File modifications"],
                "response_actions": ["Isolate endpoint", "Collect memory dump", "Analyze process tree"]
            },
            "privilege_escalation": {
                "type": "Privilege Escalation Attempt",
                "description": "Attempt to gain higher privileges on system",
                "difficulty": "Hard",
                "iocs": ["UAC bypass attempts", "Token manipulation", "Service installation"],
                "response_actions": ["Review privilege logs", "Check service configurations", "Analyze authentication events"]
            }
        }
        
        template = inject_templates.get(inject_type, inject_templates["phishing_email"])
        return {
            "id": hashlib.md5(f"{scenario.name}{datetime.datetime.now()}".encode()).hexdigest()[:8],
            "scenario": scenario.name,
            "timestamp": datetime.datetime.now().isoformat(),
            **template
        }
    
    def export_scenario(self, scenario: ExerciseScenario, format: str = "json") -> str:
        """Export scenario in specified format"""
        data = asdict(scenario)
        
        if format.lower() == "json":
            return json.dumps(data, indent=2)
        elif format.lower() == "yaml":
            return yaml.dump(data, default_flow_style=False)
        else:
            return str(data)

def main():
    parser = argparse.ArgumentParser(description="Red/Blue Exercise Scenarios Generator")
    parser.add_argument("--scenario-type", choices=["apt_simulation", "ransomware_attack", "insider_threat", "supply_chain"],
                       default="apt_simulation", help="Type of scenario to generate")
    parser.add_argument("--infrastructure", choices=["corporate_network", "industrial_control", "cloud_environment"],
                       default="corporate_network", help="Infrastructure type")
    parser.add_argument("--difficulty", choices=["Low", "Medium", "High"], default="Medium",
                       help="Exercise difficulty level")
    parser.add_argument("--format", choices=["json", "yaml", "text"], default="json",
                       help="Output format")
    parser.add_argument("--inject", action="store_true", help="Generate sample inject")
    
    args = parser.parse_args()
    
    generator = ScenarioGenerator()
    scenario = generator.generate_scenario(args.scenario_type, args.infrastructure, args.difficulty)
    
    if args.inject:
        inject = generator.generate_inject(scenario, "phishing_email")
        print(f"Generated Inject:\n{json.dumps(inject, indent=2)}")
    else:
        output = generator.export_scenario(scenario, args.format)
        print(output)

if __name__ == "__main__":
    main()
