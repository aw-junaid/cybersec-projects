"""
CLI Reporter
Generates command-line format security reports
"""

import logging
from typing import List, Dict, Any
from datetime import datetime


class CLIReporter:
    """Command-line format security report generator"""
    
    @staticmethod
    def generate_report(findings: List[Dict[str, Any]]):
        """Generate CLI security report"""
        try:
            print("\n" + "="*80)
            print("CLOUD SECURITY POSTURE MANAGEMENT REPORT")
            print("="*80)
            print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Total Findings: {len(findings)}")
            
            # Summary statistics
            severity_counts = {}
            category_counts = {}
            
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                category = finding.get('category', 'UNKNOWN')
                category_counts[category] = category_counts.get(category, 0) + 1
            
            print("\nSUMMARY:")
            print("-" * 40)
            print("Severity Breakdown:")
            for severity, count in sorted(severity_counts.items()):
                print(f"  {severity}: {count}")
                
            print("\nCategory Breakdown:")
            for category, count in sorted(category_counts.items()):
                print(f"  {category}: {count}")
            
            # Detailed findings
            print("\nDETAILED FINDINGS:")
            print("-" * 80)
            
            for i, finding in enumerate(findings, 1):
                print(f"\n{i}. [{finding.get('severity', 'UNKNOWN')}] {finding.get('title', 'No Title')}")
                print(f"   Provider: {finding.get('provider', 'Unknown')}")
                print(f"   Resource: {finding.get('resource_type', 'Unknown')} - {finding.get('resource_id', 'Unknown')}")
                print(f"   Description: {finding.get('description', 'No description')}")
                print(f"   Risk Score: {finding.get('risk_score', 'N/A')}")
                print(f"   Category: {finding.get('category', 'Unknown')}")
                
            print("\n" + "="*80)
            
        except Exception as e:
            logging.error(f"Failed to generate CLI report: {str(e)}")
