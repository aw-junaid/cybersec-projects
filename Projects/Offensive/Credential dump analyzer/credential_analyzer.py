#!/usr/bin/env python3
"""
Credential Dump Analyzer - Security Intelligence Tool
Purpose: Parse, analyze, and extract intelligence from credential dumps
Use: Security monitoring, threat intelligence, breach response, credential hygiene
"""

import re
import json
import hashlib
import pandas as pd
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from pathlib import Path
import logging
import argparse
import sqlite3
from datetime import datetime
import heapq
import itertools
from urllib.parse import urlparse
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('credential_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CredentialEntry:
    username: str
    password: str
    source: str
    domain: Optional[str] = None
    email: Optional[str] = None
    hash_type: Optional[str] = None
    hash_value: Optional[str] = None
    additional_info: Optional[Dict] = None
    leak_date: Optional[str] = None

@dataclass
class AnalysisResult:
    total_credentials: int
    unique_users: int
    unique_passwords: int
    common_passwords: List[Tuple[str, int]]
    password_patterns: Dict[str, int]
    domain_analysis: Dict[str, int]
    email_analysis: Dict[str, int]
    password_strength_stats: Dict[str, int]
    credential_reuse: Dict[str, List[str]]

class CredentialParser:
    """Parse various credential dump formats"""
    
    def __init__(self):
        self.email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.domain_pattern = re.compile(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
        self.hash_patterns = {
            'md5': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE),
            'sha1': re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE),
            'sha256': re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE),
            'ntlm': re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE),
            'bcrypt': re.compile(r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$'),
            'base64': re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        }
    
    def parse_file(self, file_path: str, source: str = "unknown") -> List[CredentialEntry]:
        """Parse credential dump file and extract credentials"""
        entries = []
        file_ext = Path(file_path).suffix.lower()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if file_ext in ['.json', '.jsonl']:
                entries = self.parse_json(content, source)
            elif file_ext in ['.csv', '.tsv']:
                entries = self.parse_csv(content, source)
            elif file_ext in ['.txt', '.log', '']:
                entries = self.parse_text(content, source)
            elif file_ext in ['.sql', '.dump']:
                entries = self.parse_sql_dump(content, source)
            else:
                entries = self.parse_generic(content, source)
                
            logger.info(f"Parsed {len(entries)} credentials from {file_path}")
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return []
    
    def parse_json(self, content: str, source: str) -> List[CredentialEntry]:
        """Parse JSON-formatted credential dumps"""
        entries = []
        
        try:
            data = json.loads(content)
            
            if isinstance(data, list):
                for item in data:
                    entry = self.extract_from_dict(item, source)
                    if entry:
                        entries.append(entry)
            elif isinstance(data, dict):
                entry = self.extract_from_dict(data, source)
                if entry:
                    entries.append(entry)
                    
        except json.JSONDecodeError:
            # Try JSONL format
            for line in content.split('\n'):
                line = line.strip()
                if line:
                    try:
                        item = json.loads(line)
                        entry = self.extract_from_dict(item, source)
                        if entry:
                            entries.append(entry)
                    except:
                        continue
        
        return entries
    
    def parse_csv(self, content: str, source: str) -> List[CredentialEntry]:
        """Parse CSV/TSV formatted credential dumps"""
        entries = []
        lines = content.split('\n')
        
        if not lines:
            return entries
        
        # Detect delimiter
        first_line = lines[0]
        delimiter = ',' if ',' in first_line else '\t'
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
                
            parts = line.split(delimiter)
            if len(parts) >= 2:
                username = parts[0].strip('"\' ')
                password = parts[1].strip('"\' ')
                
                if username and password:
                    entry = CredentialEntry(
                        username=username,
                        password=password,
                        source=source,
                        domain=self.extract_domain(username),
                        email=self.extract_email(username),
                        hash_type=self.detect_hash_type(password),
                        hash_value=password if self.detect_hash_type(password) else None,
                        additional_info={'line_number': i + 1, 'columns': len(parts)}
                    )
                    entries.append(entry)
        
        return entries
    
    def parse_text(self, content: str, source: str) -> List[CredentialEntry]:
        """Parse text-based credential dumps"""
        entries = []
        lines = content.split('\n')
        
        common_separators = [':', ';', '|', '\t', ' -> ', ' => ']
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            
            # Try common separators
            username, password = None, None
            
            for sep in common_separators:
                if sep in line:
                    parts = line.split(sep, 1)
                    if len(parts) == 2:
                        username = parts[0].strip()
                        password = parts[1].strip()
                        break
            
            # If no separator found, try splitting by whitespace
            if not username or not password:
                parts = line.split()
                if len(parts) >= 2:
                    username = parts[0]
                    password = parts[1]
            
            if username and password:
                entry = CredentialEntry(
                    username=username,
                    password=password,
                    source=source,
                    domain=self.extract_domain(username),
                    email=self.extract_email(username),
                    hash_type=self.detect_hash_type(password),
                    hash_value=password if self.detect_hash_type(password) else None,
                    additional_info={'line_number': i + 1, 'separator_used': sep if 'sep' in locals() else 'whitespace'}
                )
                entries.append(entry)
        
        return entries
    
    def parse_sql_dump(self, content: str, source: str) -> List[CredentialEntry]:
        """Parse SQL database dumps"""
        entries = []
        
        # Look for INSERT statements with potential credential data
        insert_pattern = re.compile(r'INSERT\s+INTO\s+\w+\s*\([^)]+\)\s*VALUES\s*\(([^)]+)\)', re.IGNORECASE)
        
        for match in insert_pattern.finditer(content):
            values = match.group(1)
            # Simple extraction - in real implementation, parse properly
            parts = [part.strip().strip("'\"") for part in values.split(',')]
            
            if len(parts) >= 2:
                username = parts[0]
                password = parts[1] if len(parts) > 1 else ""
                
                if username and password:
                    entry = CredentialEntry(
                        username=username,
                        password=password,
                        source=source,
                        domain=self.extract_domain(username),
                        email=self.extract_email(username),
                        hash_type=self.detect_hash_type(password),
                        hash_value=password if self.detect_hash_type(password) else None,
                        additional_info={'sql_context': 'insert_statement'}
                    )
                    entries.append(entry)
        
        return entries
    
    def parse_generic(self, content: str, source: str) -> List[CredentialEntry]:
        """Generic parser for unknown formats"""
        entries = []
        
        # Try multiple parsing strategies
        strategies = [
            self.parse_text,
            self.parse_csv
        ]
        
        for strategy in strategies:
            entries = strategy(content, source)
            if entries:
                break
        
        return entries
    
    def extract_from_dict(self, data: Dict, source: str) -> Optional[CredentialEntry]:
        """Extract credentials from dictionary object"""
        username_keys = ['username', 'user', 'email', 'login', 'account', 'uid']
        password_keys = ['password', 'pass', 'pwd', 'hash', 'password_hash']
        
        username, password = None, None
        
        # Find username
        for key in username_keys:
            if key in data and data[key]:
                username = str(data[key])
                break
        
        # Find password
        for key in password_keys:
            if key in data and data[key]:
                password = str(data[key])
                break
        
        if username and password:
            return CredentialEntry(
                username=username,
                password=password,
                source=source,
                domain=self.extract_domain(username),
                email=self.extract_email(username),
                hash_type=self.detect_hash_type(password),
                hash_value=password if self.detect_hash_type(password) else None,
                additional_info=data
            )
        
        return None
    
    def extract_email(self, text: str) -> Optional[str]:
        """Extract email address from text"""
        match = self.email_pattern.search(text)
        return match.group() if match else None
    
    def extract_domain(self, text: str) -> Optional[str]:
        """Extract domain from username/email"""
        email = self.extract_email(text)
        if email:
            match = self.domain_pattern.search(email)
            return match.group(1) if match else None
        return None
    
    def detect_hash_type(self, text: str) -> Optional[str]:
        """Detect hash type of password string"""
        for hash_type, pattern in self.hash_patterns.items():
            if pattern.match(text):
                return hash_type
        return None

class CredentialAnalyzer:
    """Analyze credential dumps for patterns and intelligence"""
    
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.password_rules = self.load_password_rules()
    
    def load_common_passwords(self) -> Set[str]:
        """Load common passwords for comparison"""
        common_passwords = {
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', 'shadow', 'master', '666666', 'qwertyuiop'
        }
        return common_passwords
    
    def load_password_rules(self) -> Dict:
        """Load password complexity rules"""
        return {
            'min_length': 8,
            'require_upper': True,
            'require_lower': True,
            'require_digit': True,
            'require_special': True,
            'max_consecutive': 3
        }
    
    def analyze_credentials(self, credentials: List[CredentialEntry]) -> AnalysisResult:
        """Perform comprehensive credential analysis"""
        logger.info(f"Analyzing {len(credentials)} credentials...")
        
        # Basic statistics
        unique_users = len(set(cred.username for cred in credentials))
        unique_passwords = len(set(cred.password for cred in credentials))
        
        # Password frequency analysis
        password_counter = Counter(cred.password for cred in credentials)
        common_passwords = password_counter.most_common(20)
        
        # Domain analysis
        domains = [cred.domain for cred in credentials if cred.domain]
        domain_analysis = Counter(domains)
        
        # Email analysis
        emails = [cred.email for cred in credentials if cred.email]
        email_analysis = Counter(emails)
        
        # Password pattern analysis
        password_patterns = self.analyze_password_patterns(credentials)
        
        # Password strength analysis
        password_strength_stats = self.analyze_password_strength(credentials)
        
        # Credential reuse analysis
        credential_reuse = self.analyze_credential_reuse(credentials)
        
        return AnalysisResult(
            total_credentials=len(credentials),
            unique_users=unique_users,
            unique_passwords=unique_passwords,
            common_passwords=common_passwords,
            password_patterns=password_patterns,
            domain_analysis=dict(domain_analysis),
            email_analysis=dict(email_analysis),
            password_strength_stats=password_strength_stats,
            credential_reuse=credential_reuse
        )
    
    def analyze_password_patterns(self, credentials: List[CredentialEntry]) -> Dict[str, int]:
        """Analyze common password patterns"""
        patterns = Counter()
        
        for cred in credentials:
            password = cred.password
            
            # Length patterns
            length = len(password)
            patterns[f'length_{length}'] += 1
            
            # Character type patterns
            if password.isdigit():
                patterns['all_digits'] += 1
            elif password.isalpha():
                patterns['all_letters'] += 1
            elif password.isalnum():
                patterns['alphanumeric'] += 1
            
            # Common patterns
            if password.lower() in self.common_passwords:
                patterns['common_password'] += 1
            
            if re.match(r'^[a-zA-Z]+\d+$', password):
                patterns['word_then_numbers'] += 1
            
            if re.match(r'^\d+[a-zA-Z]+$', password):
                patterns['numbers_then_word'] += 1
            
            if re.search(r'(\d)\1{2,}', password):  # Repeated digits
                patterns['repeated_digits'] += 1
            
            # Season/year patterns
            if re.search(r'(spring|summer|fall|winter|autumn)\s*\d{4}', password, re.IGNORECASE):
                patterns['season_year'] += 1
            
            if re.search(r'\d{4}', password):  # Contains year
                patterns['contains_year'] += 1
        
        return dict(patterns)
    
    def analyze_password_strength(self, credentials: List[CredentialEntry]) -> Dict[str, int]:
        """Analyze password strength distribution"""
        strength_stats = {
            'very_weak': 0,
            'weak': 0,
            'medium': 0,
            'strong': 0,
            'very_strong': 0
        }
        
        for cred in credentials:
            strength = self.assess_password_strength(cred.password)
            strength_stats[strength] += 1
        
        return strength_stats
    
    def assess_password_strength(self, password: str) -> str:
        """Assess individual password strength"""
        if not password:
            return 'very_weak'
        
        score = 0
        rules = self.password_rules
        
        # Length check
        if len(password) >= rules['min_length']:
            score += 1
        if len(password) >= 12:
            score += 1
        
        # Character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        if has_upper and rules['require_upper']:
            score += 1
        if has_lower and rules['require_lower']:
            score += 1
        if has_digit and rules['require_digit']:
            score += 1
        if has_special and rules['require_special']:
            score += 1
        
        # Common password check
        if password.lower() in self.common_passwords:
            score = max(0, score - 2)
        
        # Consecutive character check
        if self.has_consecutive_chars(password, rules['max_consecutive']):
            score = max(0, score - 1)
        
        # Determine strength level
        if score <= 2:
            return 'very_weak'
        elif score <= 4:
            return 'weak'
        elif score <= 6:
            return 'medium'
        elif score <= 8:
            return 'strong'
        else:
            return 'very_strong'
    
    def has_consecutive_chars(self, password: str, max_consecutive: int) -> bool:
        """Check for consecutive repeating characters"""
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count > max_consecutive:
                    return True
            else:
                count = 1
        return False
    
    def analyze_credential_reuse(self, credentials: List[CredentialEntry]) -> Dict[str, List[str]]:
        """Analyze password reuse across different users"""
        password_to_users = defaultdict(list)
        
        for cred in credentials:
            password_to_users[cred.password].append(cred.username)
        
        # Filter to passwords used by multiple users
        credential_reuse = {
            password: users 
            for password, users in password_to_users.items() 
            if len(users) > 1
        }
        
        return dict(credential_reuse)
    
    def find_compromised_accounts(self, credentials: List[CredentialEntry], 
                                target_domains: List[str]) -> List[CredentialEntry]:
        """Find credentials for specific target domains"""
        compromised = []
        
        for cred in credentials:
            if cred.domain and cred.domain.lower() in [d.lower() for d in target_domains]:
                compromised.append(cred)
        
        return compromised
    
    def generate_password_policy_recommendations(self, analysis: AnalysisResult) -> List[str]:
        """Generate password policy recommendations based on analysis"""
        recommendations = []
        
        # Weak password recommendations
        weak_percentage = (analysis.password_strength_stats['very_weak'] + 
                          analysis.password_strength_stats['weak']) / analysis.total_credentials * 100
        
        if weak_percentage > 50:
            recommendations.append(
                f"High percentage of weak passwords ({weak_percentage:.1f}%). "
                "Implement stronger password complexity requirements."
            )
        
        # Common password recommendations
        common_password_count = analysis.password_patterns.get('common_password', 0)
        if common_password_count > 0:
            recommendations.append(
                f"Found {common_password_count} instances of common passwords. "
                "Consider implementing a password blacklist."
            )
        
        # Password reuse recommendations
        if analysis.credential_reuse:
            reuse_count = sum(len(users) for users in analysis.credential_reuse.values())
            recommendations.append(
                f"Found {len(analysis.credential_reuse)} passwords reused across {reuse_count} accounts. "
                "Implement password history and prevent reuse."
            )
        
        # General recommendations
        if analysis.unique_passwords / analysis.total_credentials < 0.5:
            recommendations.append(
                "Low password uniqueness. Consider enforcing minimum password uniqueness requirements."
            )
        
        return recommendations

class CredentialStorage:
    """Store and query credential intelligence"""
    
    def __init__(self, db_path: str = "credential_intel.db"):
        self.db_path = db_path
        self.setup_database()
    
    def setup_database(self):
        """Setup SQLite database for credential storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Credentials table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                source TEXT,
                domain TEXT,
                email TEXT,
                hash_type TEXT,
                hash_value TEXT,
                leak_date TEXT,
                import_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(username, password, source)
            )
        ''')
        
        # Analysis results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_credentials INTEGER,
                unique_users INTEGER,
                unique_passwords INTEGER,
                common_passwords TEXT,
                password_patterns TEXT,
                domain_analysis TEXT,
                email_analysis TEXT,
                password_strength_stats TEXT,
                credential_reuse TEXT
            )
        ''')
        
        # Compromised accounts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compromised_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                domain TEXT,
                password TEXT,
                source TEXT,
                leak_date TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                risk_score INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Credential database setup completed")
    
    def store_credentials(self, credentials: List[CredentialEntry]):
        """Store credentials in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for cred in credentials:
            try:
                cursor.execute('''
                    INSERT OR IGNORE INTO credentials 
                    (username, password, source, domain, email, hash_type, hash_value, leak_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cred.username,
                    cred.password,
                    cred.source,
                    cred.domain,
                    cred.email,
                    cred.hash_type,
                    cred.hash_value,
                    cred.leak_date
                ))
            except Exception as e:
                logger.error(f"Error storing credential: {e}")
        
        conn.commit()
        conn.close()
        logger.info(f"Stored {len(credentials)} credentials in database")
    
    def store_analysis(self, analysis: AnalysisResult):
        """Store analysis results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_results 
            (total_credentials, unique_users, unique_passwords, common_passwords, 
             password_patterns, domain_analysis, email_analysis, password_strength_stats, credential_reuse)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis.total_credentials,
            analysis.unique_users,
            analysis.unique_passwords,
            json.dumps(analysis.common_passwords),
            json.dumps(analysis.password_patterns),
            json.dumps(analysis.domain_analysis),
            json.dumps(analysis.email_analysis),
            json.dumps(analysis.password_strength_stats),
            json.dumps(analysis.credential_reuse)
        ))
        
        conn.commit()
        conn.close()
        logger.info("Stored analysis results in database")
    
    def search_credentials(self, username: str = None, domain: str = None, 
                         email: str = None) -> List[Dict]:
        """Search for credentials in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT username, password, source, domain, email, leak_date FROM credentials WHERE 1=1"
        params = []
        
        if username:
            query += " AND username LIKE ?"
            params.append(f'%{username}%')
        
        if domain:
            query += " AND domain LIKE ?"
            params.append(f'%{domain}%')
        
        if email:
            query += " AND email LIKE ?"
            params.append(f'%{email}%')
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        conn.close()
        
        return [
            {
                'username': row[0],
                'password': row[1],
                'source': row[2],
                'domain': row[3],
                'email': row[4],
                'leak_date': row[5]
            }
            for row in results
        ]

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Credential Dump Analyzer')
    parser.add_argument('files', nargs='+', help='Credential dump files to analyze')
    parser.add_argument('--analyze', action='store_true', help='Perform comprehensive analysis')
    parser.add_argument('--search', help='Search for specific username/email')
    parser.add_argument('--domain', help='Filter by domain')
    parser.add_argument('--output', help='Output file for results')
    parser.add_argument('--store', action='store_true', help='Store results in database')
    
    args = parser.parse_args()
    
    print("Credential Dump Analyzer - Security Intelligence Tool")
    print("FOR AUTHORIZED SECURITY RESEARCH ONLY")
    print("=" * 60)
    
    # Initialize components
    parser = CredentialParser()
    analyzer = CredentialAnalyzer()
    storage = CredentialStorage()
    
    all_credentials = []
    
    # Parse all files
    for file_path in args.files:
        if Path(file_path).exists():
            credentials = parser.parse_file(file_path, Path(file_path).name)
            all_credentials.extend(credentials)
            print(f"Parsed {len(credentials)} credentials from {file_path}")
        else:
            print(f"Warning: File {file_path} not found")
    
    if not all_credentials:
        print("No credentials found to analyze")
        return
    
    if args.search:
        # Search mode
        print(f"\nSearching for: {args.search}")
        results = storage.search_credentials(username=args.search, email=args.search)
        
        if results:
            print(f"Found {len(results)} matching credentials:")
            for result in results:
                print(f"  {result['username']}:{result['password']} (Source: {result['source']})")
        else:
            print("No matching credentials found")
    
    elif args.analyze:
        # Analysis mode
        print(f"\nAnalyzing {len(all_credentials)} credentials...")
        
        # Perform analysis
        analysis = analyzer.analyze_credentials(all_credentials)
        
        # Generate report
        report = generate_report(analysis, all_credentials)
        
        # Store results if requested
        if args.store:
            storage.store_credentials(all_credentials)
            storage.store_analysis(analysis)
            print("Results stored in database")
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to: {args.output}")
        else:
            print_report(report)
    
    else:
        print(f"Loaded {len(all_credentials)} credentials")
        print("Use --analyze for comprehensive analysis or --search to find specific credentials")

def generate_report(analysis: AnalysisResult, credentials: List[CredentialEntry]) -> Dict:
    """Generate comprehensive analysis report"""
    report = {
        'summary': {
            'total_credentials': analysis.total_credentials,
            'unique_users': analysis.unique_users,
            'unique_passwords': analysis.unique_passwords,
            'analysis_timestamp': datetime.now().isoformat()
        },
        'password_analysis': {
            'common_passwords': analysis.common_passwords,
            'password_patterns': analysis.password_patterns,
            'password_strength': analysis.password_strength_stats
        },
        'domain_analysis': analysis.domain_analysis,
        'credential_reuse': analysis.credential_reuse,
        'recommendations': []
    }
    
    # Add recommendations
    analyzer = CredentialAnalyzer()
    recommendations = analyzer.generate_password_policy_recommendations(analysis)
    report['recommendations'] = recommendations
    
    return report

def print_report(report: Dict):
    """Print analysis report to console"""
    print("\n" + "=" * 60)
    print("CREDENTIAL DUMP ANALYSIS REPORT")
    print("=" * 60)
    
    summary = report['summary']
    print(f"\nSUMMARY:")
    print(f"  Total credentials: {summary['total_credentials']}")
    print(f"  Unique users: {summary['unique_users']}")
    print(f"  Unique passwords: {summary['unique_passwords']}")
    print(f"  Password reuse ratio: {summary['unique_passwords']/summary['total_credentials']:.2f}")
    
    password_analysis = report['password_analysis']
    print(f"\nPASSWORD ANALYSIS:")
    print(f"  Most common passwords:")
    for password, count in password_analysis['common_passwords'][:10]:
        print(f"    {password}: {count} occurrences")
    
    print(f"\n  Password strength distribution:")
    for strength, count in password_analysis['password_strength'].items():
        percentage = (count / summary['total_credentials']) * 100
        print(f"    {strength}: {count} ({percentage:.1f}%)")
    
    if report['domain_analysis']:
        print(f"\nDOMAIN ANALYSIS (Top 10):")
        domains_sorted = sorted(report['domain_analysis'].items(), key=lambda x: x[1], reverse=True)[:10]
        for domain, count in domains_sorted:
            print(f"    {domain}: {count} credentials")
    
    if report['credential_reuse']:
        print(f"\nCREDENTIAL REUSE:")
        reuse_sorted = sorted(report['credential_reuse'].items(), key=lambda x: len(x[1]), reverse=True)[:5]
        for password, users in reuse_sorted:
            print(f"  Password '{password}' used by {len(users)} users: {', '.join(users[:3])}...")
    
    if report['recommendations']:
        print(f"\nRECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"  • {rec}")
    
    print("=" * 60)

if __name__ == "__main__":
    main()
