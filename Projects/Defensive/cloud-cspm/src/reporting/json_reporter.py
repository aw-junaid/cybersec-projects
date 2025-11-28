"""
JSON Reporter
Generates JSON format security reports
"""

import json
import logging
from datetime import datetime
from typing import List, Dict, Any


class JSONReporter:
    """JSON format security report generator"""
    
    @staticmethod
    def generate_report(findings: List[Dict[str, Any]], output_file: str = 'security_report.json'):
        """Generate JSON security report"""
        try:
            report = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_findings': len(findings),
                    'scan_summary': JSONReporter._generate_summary(findings)
                },
                'findings': findings
            }
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
                
            logging.info(f"JSON report generated: {output_file}")
            
        except Exception as e:
            logging.error(f"Failed to generate JSON report: {str(e)}")
    
    @staticmethod
    def _generate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate report summary"""
        severity_counts = {}
        category_counts = {}
        provider_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            category = finding.get('category', 'UNKNOWN')
            category_counts[category] = category_counts.get(category, 0) + 1
            
            provider = finding.get('provider', 'UNKNOWN')
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        return {
            'severity_breakdown': severity_counts,
            'category_breakdown': category_counts,
            'provider_breakdown': provider_counts
        }
