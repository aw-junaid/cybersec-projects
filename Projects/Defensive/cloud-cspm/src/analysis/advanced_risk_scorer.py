"""
Advanced risk scoring with CVE, MITRE ATT&CK, and compliance mapping
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime


class AdvancedRiskScorer:
    """Advanced risk scoring with multiple frameworks"""
    
    def __init__(self):
        self.mitre_techniques = self.load_mitre_techniques()
        self.cve_scores = self.load_cve_data()
        self.compliance_frameworks = self.load_compliance_frameworks()
        
    def calculate_advanced_risk_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk score"""
        base_score = self.calculate_base_risk(finding)
        
        # Apply MITRE ATT&CK adjustments
        mitre_score = self.apply_mitre_scoring(finding, base_score)
        
        # Apply CVE adjustments if applicable
        cve_score = self.apply_cve_scoring(finding, mitre_score)
        
        # Apply compliance impact
        compliance_score = self.apply_compliance_scoring(finding, cve_score)
        
        # Apply temporal factors
        final_score = self.apply_temporal_factors(finding, compliance_score)
        
        return {
            'risk_score': round(final_score, 2),
            'severity': self.score_to_severity(final_score),
            'mitre_techniques': self.get_mitre_techniques(finding),
            'compliance_impacts': self.get_compliance_impacts(finding),
            'base_score': round(base_score, 2),
            'mitre_adjustment': round(mitre_score - base_score, 2),
            'cve_adjustment': round(cve_score - mitre_score, 2),
            'compliance_adjustment': round(compliance_score - cve_score, 2)
        }
    
    def apply_mitre_scoring(self, finding: Dict[str, Any], base_score: float) -> float:
        """Apply MITRE ATT&CK technique scoring"""
        techniques = self.get_mitre_techniques(finding)
        
        if not techniques:
            return base_score
            
        # Increase score based on MITRE technique prevalence and impact
        technique_boost = 0.0
        for technique in techniques:
            if technique.get('tactics'):
                technique_boost += 0.5
            if technique.get('platforms') and 'Cloud' in technique['platforms']:
                technique_boost += 0.3
                
        return min(10.0, base_score + technique_boost)
    
    def apply_cve_scoring(self, finding: Dict[str, Any], current_score: float) -> float:
        """Apply CVE-based scoring if vulnerabilities are involved"""
        if 'cves' in finding.get('details', {}):
            cves = finding['details']['cves']
            max_cvss = 0.0
            
            for cve in cves:
                cvss_score = self.cve_scores.get(cve, {}).get('cvss_score', 0.0)
                max_cvss = max(max_cvss, cvss_score)
                
            # Blend CVE score with current risk score
            if max_cvss > 0:
                return (current_score * 0.7) + (max_cvss * 0.3)
                
        return current_score
    
    def apply_compliance_scoring(self, finding: Dict[str, Any], current_score: float) -> float:
        """Apply compliance framework impact scoring"""
        impacts = self.get_compliance_impacts(finding)
        
        if not impacts:
            return current_score
            
        compliance_boost = 0.0
        for framework, controls in impacts.items():
            # Higher boost for critical compliance controls
            if any(control.get('severity') == 'HIGH' for control in controls):
                compliance_boost += 1.0
            elif any(control.get('severity') == 'MEDIUM' for control in controls):
                compliance_boost += 0.5
                
        return min(10.0, current_score + compliance_boost)
    
    def apply_temporal_factors(self, finding: Dict[str, Any], current_score: float) -> float:
        """Apply temporal factors to risk scoring"""
        # Reduce score for older findings if they haven't been exploited
        if 'first_observed' in finding:
            days_old = (datetime.now() - finding['first_observed']).days
            if days_old > 30 and not finding.get('exploited', False):
                current_score *= 0.9  # 10% reduction for old, unexploited findings
                
        # Increase score for findings in production environments
        if finding.get('environment') == 'production':
            current_score *= 1.1  # 10% increase for production
            
        return min(10.0, current_score)
    
    def load_mitre_techniques(self) -> Dict[str, Any]:
        """Load MITRE ATT&CK techniques relevant to cloud security"""
        return {
            'T1078.004': {  # Cloud Accounts
                'name': 'Valid Accounts - Cloud Accounts',
                'tactics': ['Persistence', 'Defense Evasion', 'Initial Access'],
                'platforms': ['IaaS', 'SaaS', 'PaaS']
            },
            'T1530': {  # Data from Cloud Storage
                'name': 'Data from Cloud Storage',
                'tactics': ['Collection'],
                'platforms': ['IaaS', 'SaaS']
            },
            'T1552.005': {  # Cloud API Keys
                'name': 'Unsecured Credentials - Cloud API Keys',
                'tactics': ['Credential Access'],
                'platforms': ['IaaS', 'PaaS']
            }
        }
    
    def load_cve_data(self) -> Dict[str, Any]:
        """Load CVE data for vulnerability scoring"""
        # In real implementation, this would fetch from CVE databases
        return {}
    
    def load_compliance_frameworks(self) -> Dict[str, Any]:
        """Load compliance framework mappings"""
        return {
            'CIS': {
                'CIS-1.1': {'severity': 'HIGH', 'description': 'Avoid root account usage'},
                'CIS-1.2': {'severity': 'HIGH', 'description': 'Enable MFA for all users'}
            },
            'NIST': {
                'NIST-1.1': {'severity': 'MEDIUM', 'description': 'Access control policies'},
                'NIST-2.2': {'severity': 'HIGH', 'description': 'Data protection'}
            },
            'PCI-DSS': {
                'PCI-1.2': {'severity': 'HIGH', 'description': 'Firewall configuration'},
                'PCI-3.4': {'severity': 'MEDIUM', 'description': 'Data encryption'}
            }
        }
    
    def get_mitre_techniques(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get relevant MITRE techniques for a finding"""
        techniques = []
        finding_type = finding.get('finding_type', '')
        
        # Map finding types to MITRE techniques
        mitre_mapping = {
            'PUBLIC_BUCKET': ['T1530'],
            'NO_MFA': ['T1078.004'],
            'EXPOSED_KEYS': ['T1552.005'],
            'OVERLY_PERMISSIVE_ROLE': ['T1078.004']
        }
        
        for technique_id in mitre_mapping.get(finding_type, []):
            if technique_id in self.mitre_techniques:
                techniques.append(self.mitre_techniques[technique_id])
                
        return techniques
    
    def get_compliance_impacts(self, finding: Dict[str, Any]) -> Dict[str, List[str]]:
        """Get compliance framework impacts for a finding"""
        impacts = {}
        finding_type = finding.get('finding_type', '')
        
        # Map finding types to compliance controls
        compliance_mapping = {
            'PUBLIC_BUCKET': {
                'CIS': ['CIS-2.1.3'],
                'NIST': ['NIST-3.1.12'],
                'PCI-DSS': ['PCI-3.4']
            },
            'NO_MFA': {
                'CIS': ['CIS-1.2'],
                'NIST': ['NIST-2.1.1'],
                'PCI-DSS': ['PCI-8.2']
            }
        }
        
        return compliance_mapping.get(finding_type, {})
    
    def score_to_severity(self, score: float) -> str:
        """Convert numerical score to severity level"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 5.0:
            return 'MEDIUM'
        elif score >= 3.0:
            return 'LOW'
        else:
            return 'INFO'
