"""
Risk Scoring Engine
Calculates risk scores for security findings
"""

import logging
from typing import Dict, Any, List


class RiskScorer:
    """Risk scoring engine for security findings"""
    
    def __init__(self):
        self.severity_weights = {
            'CRITICAL': 10.0,
            'HIGH': 8.0,
            'MEDIUM': 5.0,
            'LOW': 2.0,
            'INFO': 0.5
        }
        
        self.category_weights = {
            'IAM': 1.2,
            'Network': 1.1,
            'Storage': 1.0,
            'Compute': 1.0,
            'Monitoring': 0.8,
            'Compliance': 0.9
        }
        
        self.finding_type_weights = {
            'PUBLIC_BUCKET': 9.0,
            'OPEN_SECURITY_GROUP': 8.5,
            'NO_MFA': 8.0,
            'ADMIN_PRIVILEGES': 9.5,
            'WILDCARD_TRUST_POLICY': 8.5,
            'OLD_ACCESS_KEY': 6.0,
            'UNENCRYPTED_BUCKET': 7.0,
            'INLINE_POLICY': 4.0,
            'OVERLY_PERMISSIVE_BUCKET_POLICY': 8.0
        }
        
        self.logger = logging.getLogger(__name__)
    
    def calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """Calculate risk score for a security finding"""
        try:
            base_score = 0.0
            
            # Start with severity weight
            severity = finding.get('severity', 'MEDIUM')
            base_score += self.severity_weights.get(severity, 5.0)
            
            # Multiply by category weight
            category = finding.get('category', 'General')
            category_weight = self.category_weights.get(category, 1.0)
            base_score *= category_weight
            
            # Add finding type weight
            finding_type = finding.get('finding_type', '')
            finding_weight = self.finding_type_weights.get(finding_type, 5.0)
            base_score += finding_weight
            
            # Normalize to 0-10 scale
            risk_score = min(10.0, base_score / 3.0)
            
            return round(risk_score, 2)
            
        except Exception as e:
            self.logger.error(f"Error calculating risk score: {str(e)}")
            return 5.0  # Default medium risk
    
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
    
    def calculate_aggregate_risk(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate aggregate risk scores for all findings"""
        if not findings:
            return {
                'overall_risk_score': 0.0,
                'severity_breakdown': {},
                'category_breakdown': {},
                'total_findings': 0
            }
        
        total_score = 0.0
        severity_counts = {}
        category_counts = {}
        
        for finding in findings:
            risk_score = finding.get('risk_score', 0.0)
            total_score += risk_score
            
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            category = finding.get('category', 'UNKNOWN')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Calculate weighted overall risk
        max_possible_score = len(findings) * 10.0
        overall_risk = (total_score / max_possible_score) * 10.0 if max_possible_score > 0 else 0.0
        
        return {
            'overall_risk_score': round(overall_risk, 2),
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'total_findings': len(findings)
        }
