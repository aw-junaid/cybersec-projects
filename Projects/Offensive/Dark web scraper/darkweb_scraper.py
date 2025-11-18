#!/usr/bin/env python3
"""
Dark Web Scraper - Threat Intelligence Aggregation
Purpose: Research and aggregate threat intelligence from various sources
Use: Security research, threat intelligence, cyber threat monitoring
"""

import requests
import json
import time
import hashlib
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
import logging
from bs4 import BeautifulSoup
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import os
from urllib.parse import urljoin, urlparse
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('threat_intel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatType(Enum):
    MALWARE = "malware"
    EXPLOIT = "exploit"
    DATA_BREACH = "data_breach"
    CREDENTIALS = "credentials"
    VULNERABILITY = "vulnerability"
    IOCs = "iocs"  # Indicators of Compromise

@dataclass
class ThreatIntel:
    source: str
    threat_type: ThreatType
    title: str
    description: str
    raw_data: str
    confidence: float
    timestamp: datetime
    iocs: List[str]
    tags: List[str]

class DarkWebScraper:
    def __init__(self, config_file="threat_config.json"):
        self.config = self.load_config(config_file)
        self.session = self.create_session()
        self.intel_database = "threat_intel.db"
        self.setup_database()
        self.proxies = self.config.get('proxies', {})
        
    def load_config(self, config_file: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "sources": {
                "paste_sites": [
                    "https://pastebin.com",
                    "https://rentry.co",
                    "https://ghostbin.com"
                ],
                "forums": [
                    "https://forum.example-onion-site.com"  # Placeholder
                ],
                "telegram_channels": [
                    "@threat_intel_channel"  # Placeholder
                ]
            },
            "scraping": {
                "delay_between_requests": 2,
                "max_pages_per_source": 100,
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
                ],
                "timeout": 30
            },
            "analysis": {
                "extract_iocs": True,
                "extract_cves": True,
                "confidence_threshold": 0.3
            },
            "security": {
                "use_tor": False,
                "tor_proxy": "socks5://127.0.0.1:9050",
                "rate_limiting": True
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
    
    def create_session(self):
        """Create requests session with appropriate headers"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(self.config['scraping']['user_agents']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        if self.config['security']['use_tor']:
            session.proxies = {
                'http': self.config['security']['tor_proxy'],
                'https': self.config['security']['tor_proxy']
            }
        
        return session
    
    def setup_database(self):
        """Setup SQLite database for threat intelligence"""
        conn = sqlite3.connect(self.intel_database)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT,
                threat_type TEXT,
                title TEXT,
                description TEXT,
                raw_data TEXT,
                confidence REAL,
                timestamp DATETIME,
                iocs TEXT,
                tags TEXT,
                hash TEXT UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT,
                ioc_type TEXT,
                threat_id INTEGER,
                source TEXT,
                first_seen DATETIME,
                last_seen DATETIME,
                FOREIGN KEY (threat_id) REFERENCES threat_intel (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                last_scraped DATETIME,
                status TEXT,
                page_count INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Threat intelligence database setup completed")
    
    def scrape_pastebin_sites(self):
        """Scrape paste sites for threat intelligence"""
        logger.info("Starting paste site scraping...")
        
        for site in self.config['sources']['paste_sites']:
            try:
                if "pastebin.com" in site:
                    self.scrape_pastebin_com(site)
                elif "rentry.co" in site:
                    self.scrape_rentry_co(site)
                elif "ghostbin.com" in site:
                    self.scrape_ghostbin_com(site)
                
                self.respect_rate_limit()
                
            except Exception as e:
                logger.error(f"Error scraping {site}: {e}")
    
    def scrape_pastebin_com(self, base_url: str):
        """Scrape Pastebin.com for recent pastes"""
        logger.info(f"Scraping Pastebin: {base_url}")
        
        # Note: Pastebin requires API access for proper scraping
        # This is a simplified example for educational purposes
        
        try:
            # Recent pastes page (this might not work without API)
            recent_url = f"{base_url}/archive"
            response = self.session.get(recent_url, timeout=self.config['scraping']['timeout'])
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract paste links (this structure may change)
                paste_links = []
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if '/raw/' in href or href.startswith('/'):
                        full_url = urljoin(base_url, href)
                        paste_links.append(full_url)
                
                # Process a limited number of pastes
                for paste_url in paste_links[:10]:
                    self.process_paste(paste_url, "pastebin")
                    self.respect_rate_limit()
            
        except Exception as e:
            logger.error(f"Error scraping Pastebin: {e}")
    
    def scrape_rentry_co(self, base_url: str):
        """Scrape Rentry.co for pastes"""
        logger.info(f"Scraping Rentry: {base_url}")
        
        try:
            # Rentry has a simple structure - we can try common URLs
            common_paths = ['/test', '/demo', '/example', '/paste']
            
            for path in common_paths:
                paste_url = base_url + path
                self.process_paste(paste_url, "rentry")
                self.respect_rate_limit()
                
        except Exception as e:
            logger.error(f"Error scraping Rentry: {e}")
    
    def scrape_ghostbin_com(self, base_url: str):
        """Scrape Ghostbin.com for pastes"""
        logger.info(f"Scraping Ghostbin: {base_url}")
        
        try:
            # Ghostbin example - would need proper implementation
            # This is a placeholder for the scraping logic
            pass
            
        except Exception as e:
            logger.error(f"Error scraping Ghostbin: {e}")
    
    def process_paste(self, paste_url: str, source: str):
        """Process individual paste and extract threat intelligence"""
        try:
            response = self.session.get(paste_url, timeout=self.config['scraping']['timeout'])
            
            if response.status_code == 200:
                content = response.text
                
                # Analyze content for threat indicators
                threat_type, confidence, iocs, tags = self.analyze_content(content)
                
                if confidence >= self.config['analysis']['confidence_threshold']:
                    # Create threat intel object
                    intel = ThreatIntel(
                        source=source,
                        threat_type=threat_type,
                        title=f"Paste from {source}",
                        description=f"Content scraped from {paste_url}",
                        raw_data=content[:1000],  # Store first 1000 chars
                        confidence=confidence,
                        timestamp=datetime.now(),
                        iocs=iocs,
                        tags=tags
                    )
                    
                    # Store in database
                    self.store_threat_intel(intel)
                    logger.info(f"Found threat intel: {threat_type.value} (confidence: {confidence})")
            
        except Exception as e:
            logger.error(f"Error processing paste {paste_url}: {e}")
    
    def analyze_content(self, content: str) -> tuple:
        """Analyze content for threat indicators"""
        threat_type = ThreatType.IOCs
        confidence = 0.0
        iocs = []
        tags = []
        
        # Extract IOCs
        if self.config['analysis']['extract_iocs']:
            iocs = self.extract_iocs(content)
        
        # Extract CVEs
        if self.config['analysis']['extract_cves']:
            cves = self.extract_cves(content)
            iocs.extend(cves)
        
        # Determine threat type and confidence
        if iocs:
            confidence = min(1.0, len(iocs) * 0.1)
            
            # Classify based on IOC types
            ip_count = len([ioc for ioc in iocs if self.is_ip_address(ioc)])
            domain_count = len([ioc for ioc in iocs if self.is_domain(ioc)])
            hash_count = len([ioc for ioc in iocs if self.is_hash(ioc)])
            cve_count = len([ioc for ioc in iocs if ioc.startswith('CVE-')])
            
            if cve_count > 0:
                threat_type = ThreatType.VULNERABILITY
                confidence += 0.3
            if hash_count > 0:
                threat_type = ThreatType.MALWARE
                confidence += 0.2
            if "exploit" in content.lower():
                threat_type = ThreatType.EXPLOIT
                confidence += 0.2
            if "password" in content.lower() or "login" in content.lower():
                threat_type = ThreatType.CREDENTIALS
                confidence += 0.2
        
        # Add tags based on content analysis
        content_lower = content.lower()
        if any(word in content_lower for word in ['malware', 'trojan', 'virus']):
            tags.append('malware')
        if any(word in content_lower for word in ['exploit', 'vulnerability', '0day']):
            tags.append('exploit')
        if any(word in content_lower for word in ['breach', 'leak', 'dump']):
            tags.append('data_breach')
        if any(word in content_lower for word in ['credential', 'password', 'account']):
            tags.append('credentials')
        
        return threat_type, min(confidence, 1.0), iocs, tags
    
    def extract_iocs(self, content: str) -> List[str]:
        """Extract Indicators of Compromise from content"""
        iocs = []
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs.extend(re.findall(ip_pattern, content))
        
        # Domains
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
        iocs.extend(re.findall(domain_pattern, content))
        
        # MD5 hashes
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        iocs.extend(re.findall(md5_pattern, content))
        
        # SHA1 hashes
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        iocs.extend(re.findall(sha1_pattern, content))
        
        # SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        iocs.extend(re.findall(sha256_pattern, content))
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs.extend(re.findall(url_pattern, content))
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs.extend(re.findall(email_pattern, content))
        
        return list(set(iocs))  # Remove duplicates
    
    def extract_cves(self, content: str) -> List[str]:
        """Extract CVE identifiers from content"""
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return re.findall(cve_pattern, content, re.IGNORECASE)
    
    def is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address"""
        ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        return bool(re.match(ip_pattern, text))
    
    def is_domain(self, text: str) -> bool:
        """Check if text is a domain"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})$'
        return bool(re.match(domain_pattern, text))
    
    def is_hash(self, text: str) -> bool:
        """Check if text is a hash"""
        if len(text) == 32 and re.match(r'^[a-fA-F0-9]{32}$', text):
            return True  # MD5
        elif len(text) == 40 and re.match(r'^[a-fA-F0-9]{40}$', text):
            return True  # SHA1
        elif len(text) == 64 and re.match(r'^[a-fA-F0-9]{64}$', text):
            return True  # SHA256
        return False
    
    def store_threat_intel(self, intel: ThreatIntel):
        """Store threat intelligence in database"""
        conn = sqlite3.connect(self.intel_database)
        cursor = conn.cursor()
        
        # Create hash for deduplication
        content_hash = hashlib.md5(
            f"{intel.source}{intel.raw_data}{intel.timestamp}".encode()
        ).hexdigest()
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO threat_intel 
                (source, threat_type, title, description, raw_data, confidence, timestamp, iocs, tags, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                intel.source,
                intel.threat_type.value,
                intel.title,
                intel.description,
                intel.raw_data,
                intel.confidence,
                intel.timestamp.isoformat(),
                json.dumps(intel.iocs),
                json.dumps(intel.tags),
                content_hash
            ))
            
            threat_id = cursor.lastrowid
            
            # Store IOCs separately
            for ioc in intel.iocs:
                ioc_type = self.classify_ioc_type(ioc)
                cursor.execute('''
                    INSERT OR IGNORE INTO iocs (ioc, ioc_type, threat_id, source, first_seen)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ioc, ioc_type, threat_id, intel.source, intel.timestamp.isoformat()))
            
            conn.commit()
            logger.info(f"Stored threat intel with {len(intel.iocs)} IOCs")
            
        except Exception as e:
            logger.error(f"Error storing threat intel: {e}")
        finally:
            conn.close()
    
    def classify_ioc_type(self, ioc: str) -> str:
        """Classify IOC type"""
        if self.is_ip_address(ioc):
            return "ip"
        elif self.is_domain(ioc):
            return "domain"
        elif self.is_hash(ioc):
            if len(ioc) == 32:
                return "md5"
            elif len(ioc) == 40:
                return "sha1"
            elif len(ioc) == 64:
                return "sha256"
        elif ioc.startswith('CVE-'):
            return "cve"
        elif ioc.startswith('http'):
            return "url"
        elif '@' in ioc:
            return "email"
        else:
            return "unknown"
    
    def respect_rate_limit(self):
        """Respect rate limiting between requests"""
        delay = self.config['scraping']['delay_between_requests']
        time.sleep(delay * random.uniform(0.8, 1.2))  # Add some randomness
    
    def search_threat_intel(self, query: str, threat_type: ThreatType = None, 
                           min_confidence: float = 0.0) -> List[ThreatIntel]:
        """Search threat intelligence database"""
        conn = sqlite3.connect(self.intel_database)
        cursor = conn.cursor()
        
        sql = '''
            SELECT source, threat_type, title, description, raw_data, confidence, timestamp, iocs, tags
            FROM threat_intel 
            WHERE (title LIKE ? OR description LIKE ? OR raw_data LIKE ?)
        '''
        params = [f'%{query}%', f'%{query}%', f'%{query}%']
        
        if threat_type:
            sql += ' AND threat_type = ?'
            params.append(threat_type.value)
        
        if min_confidence > 0:
            sql += ' AND confidence >= ?'
            params.append(min_confidence)
        
        sql += ' ORDER BY confidence DESC, timestamp DESC'
        
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            intel = ThreatIntel(
                source=row[0],
                threat_type=ThreatType(row[1]),
                title=row[2],
                description=row[3],
                raw_data=row[4],
                confidence=row[5],
                timestamp=datetime.fromisoformat(row[6]),
                iocs=json.loads(row[7]),
                tags=json.loads(row[8])
            )
            results.append(intel)
        
        conn.close()
        return results
    
    def generate_threat_report(self, days: int = 7) -> Dict:
        """Generate threat intelligence report"""
        conn = sqlite3.connect(self.intel_database)
        cursor = conn.cursor()
        
        # Get statistics
        since_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total_threats,
                COUNT(DISTINCT source) as unique_sources,
                AVG(confidence) as avg_confidence
            FROM threat_intel 
            WHERE timestamp >= ?
        ''', (since_date,))
        
        stats = cursor.fetchone()
        
        # Get threat type distribution
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count
            FROM threat_intel 
            WHERE timestamp >= ?
            GROUP BY threat_type
            ORDER BY count DESC
        ''', (since_date,))
        
        threat_distribution = cursor.fetchall()
        
        # Get top IOCs
        cursor.execute('''
            SELECT ioc, ioc_type, COUNT(*) as occurrence_count
            FROM iocs 
            WHERE first_seen >= ?
            GROUP BY ioc
            ORDER BY occurrence_count DESC
            LIMIT 20
        ''', (since_date,))
        
        top_iocs = cursor.fetchall()
        
        # Get recent high-confidence threats
        cursor.execute('''
            SELECT source, threat_type, title, confidence, timestamp
            FROM threat_intel 
            WHERE timestamp >= ? AND confidence >= 0.7
            ORDER BY confidence DESC, timestamp DESC
            LIMIT 10
        ''', (since_date,))
        
        recent_threats = cursor.fetchall()
        
        conn.close()
        
        report = {
            'report_date': datetime.now().isoformat(),
            'period_days': days,
            'statistics': {
                'total_threats': stats[0],
                'unique_sources': stats[1],
                'average_confidence': round(stats[2], 2) if stats[2] else 0
            },
            'threat_distribution': [
                {'type': row[0], 'count': row[1]} for row in threat_distribution
            ],
            'top_iocs': [
                {'ioc': row[0], 'type': row[1], 'occurrences': row[2]} for row in top_iocs
            ],
            'recent_high_confidence_threats': [
                {
                    'source': row[0],
                    'type': row[1],
                    'title': row[2],
                    'confidence': row[3],
                    'timestamp': row[4]
                } for row in recent_threats
            ]
        }
        
        return report

class ThreatIntelligenceAPI:
    """Integration with threat intelligence APIs"""
    
    def __init__(self):
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    def check_virustotal(self, ioc: str, ioc_type: str) -> Dict:
        """Check IOC with VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            url = f"https://www.virustotal.com/api/v3/{ioc_type}s/{ioc}"
            headers = {'x-apikey': self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f"VirusTotal API error: {response.status_code}"}
                
        except Exception as e:
            return {'error': f"VirusTotal check failed: {e}'}
    
    def check_abuseipdb(self, ip: str) -> Dict:
        """Check IP with AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return {'error': 'AbuseIPDB API key not configured'}
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f"AbuseIPDB API error: {response.status_code}"}
                
        except Exception as e:
            return {'error': f"AbuseIPDB check failed: {e}'}

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description='Dark Web Scraper - Threat Intelligence')
    parser.add_argument('--scrape', action='store_true', help='Start scraping')
    parser.add_argument('--search', help='Search threat intelligence database')
    parser.add_argument('--threat-type', choices=[t.value for t in ThreatType], 
                       help='Filter by threat type')
    parser.add_argument('--min-confidence', type=float, default=0.0, 
                       help='Minimum confidence threshold')
    parser.add_argument('--generate-report', type=int, default=7, 
                       help='Generate report for last N days')
    parser.add_argument('--check-ioc', help='Check IOC with external services')
    
    args = parser.parse_args()
    
    scraper = DarkWebScraper()
    
    if args.scrape:
        print("Starting threat intelligence scraping...")
        scraper.scrape_pastebin_sites()
        print("Scraping completed")
    
    elif args.search:
        print(f"Searching for: {args.search}")
        threat_type = ThreatType(args.threat_type) if args.threat_type else None
        results = scraper.search_threat_intel(args.search, threat_type, args.min_confidence)
        
        print(f"Found {len(results)} results:")
        for result in results:
            print(f"\nSource: {result.source}")
            print(f"Type: {result.threat_type.value}")
            print(f"Confidence: {result.confidence}")
            print(f"IOCs: {', '.join(result.iocs[:5])}...")
    
    elif args.generate_report:
        report = scraper.generate_threat_report(args.generate_report)
        print("Threat Intelligence Report:")
        print(json.dumps(report, indent=2))
    
    elif args.check_ioc:
        api = ThreatIntelligenceAPI()
        print(f"Checking IOC: {args.check_ioc}")
        
        # Determine IOC type
        if scraper.is_ip_address(args.check_ioc):
            result = api.check_abuseipdb(args.check_ioc)
            print("AbuseIPDB Result:")
            print(json.dumps(result, indent=2))
        else:
            ioc_type = scraper.classify_ioc_type(args.check_ioc)
            result = api.check_virustotal(args.check_ioc, ioc_type)
            print("VirusTotal Result:")
            print(json.dumps(result, indent=2))
    
    else:
        print("Dark Web Scraper - Threat Intelligence Aggregation")
        print("Use --help for available commands")

if __name__ == "__main__":
    main()
