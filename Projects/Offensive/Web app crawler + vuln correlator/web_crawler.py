#!/usr/bin/env python3
"""
Web App Crawler + Vulnerability Correlator
Purpose: Crawl web applications, find vulnerabilities, and correlate attack paths
Use: Comprehensive web application security assessment, penetration testing
"""

import requests
import threading
import queue
import time
import re
import json
import urllib.parse
from bs4 import BeautifulSoup
from collections import defaultdict, deque
from urllib.robotparser import RobotFileParser
from datetime import datetime
import argparse
import sqlite3
import networkx as nx
import matplotlib.pyplot as plt

class WebAppCrawler:
    def __init__(self, base_url, max_threads=10, max_pages=1000):
        self.base_url = base_url.rstrip('/')
        self.domain = urllib.parse.urlparse(base_url).netloc
        self.max_threads = max_threads
        self.max_pages = max_pages
        
        # Data structures
        self.visited_urls = set()
        self.to_crawl = queue.Queue()
        self.discovered_urls = set()
        self.forms = []
        self.endpoints = []
        self.vulnerabilities = []
        self.session = requests.Session()
        
        # Statistics
        self.stats = {
            'pages_crawled': 0,
            'forms_found': 0,
            'endpoints_found': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'end_time': None
        }
        
        # Configure session
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        # Attack graph
        self.attack_graph = nx.DiGraph()
        
        # Add base URL to crawl queue
        self.to_crawl.put(base_url)
        self.visited_urls.add(base_url)

    def check_robots_txt(self):
        """Check robots.txt for crawling permissions"""
        robots_url = f"{self.base_url}/robots.txt"
        try:
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                print(f"[ROBOTS] Found robots.txt at {robots_url}")
                return response.text
        except:
            pass
        return None

    def extract_links(self, html_content, current_url):
        """Extract all links from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        # Extract href links
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = self.normalize_url(href, current_url)
            if full_url and self.is_same_domain(full_url):
                links.append(full_url)
        
        # Extract form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = self.normalize_url(action, current_url)
            if full_url and self.is_same_domain(full_url):
                method = form.get('method', 'GET').upper()
                inputs = []
                
                for input_tag in form.find_all('input'):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    inputs.append(input_info)
                
                self.forms.append({
                    'url': full_url,
                    'method': method,
                    'inputs': inputs,
                    'source_page': current_url
                })
                self.stats['forms_found'] += 1
        
        # Extract script and link resources
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = self.normalize_url(src, current_url)
            if full_url and self.is_same_domain(full_url):
                self.endpoints.append({
                    'type': 'script',
                    'url': full_url,
                    'source_page': current_url
                })
        
        for link in soup.find_all('link', href=True):
            href = link['href']
            full_url = self.normalize_url(href, current_url)
            if full_url and self.is_same_domain(full_url):
                self.endpoints.append({
                    'type': 'resource',
                    'url': full_url,
                    'source_page': current_url
                })
        
        return links

    def normalize_url(self, url, base_url):
        """Normalize URL to absolute form"""
        if url.startswith('javascript:') or url.startswith('mailto:'):
            return None
        
        if url.startswith('//'):
            url = 'https:' + url if self.base_url.startswith('https') else 'http:' + url
        
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                # Relative URL
                base_parsed = urllib.parse.urlparse(base_url)
                full_url = urllib.parse.urljoin(base_url, url)
                parsed = urllib.parse.urlparse(full_url)
            
            # Remove fragments
            normalized = parsed._replace(fragment='').geturl()
            
            # Ensure proper encoding
            return urllib.parse.unquote(normalized)
        except:
            return None

    def is_same_domain(self, url):
        """Check if URL belongs to the same domain"""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc == self.domain or parsed.netloc.endswith('.' + self.domain)
        except:
            return False

    def crawl_page(self, url):
        """Crawl a single page"""
        if url in self.visited_urls:
            return
        
        if self.stats['pages_crawled'] >= self.max_pages:
            return
        
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            self.stats['pages_crawled'] += 1
            
            print(f"[CRAWL] [{self.stats['pages_crawled']}] {url} - Status: {response.status_code}")
            
            if response.status_code == 200:
                # Extract links and add to queue
                links = self.extract_links(response.text, url)
                
                for link in links:
                    if link not in self.visited_urls and link not in self.discovered_urls:
                        self.discovered_urls.add(link)
                        self.to_crawl.put(link)
                
                # Add to attack graph
                self.attack_graph.add_node(url, type='page', status=response.status_code)
                
                # Store page content for later analysis
                self.analyze_page_content(url, response.text, response.headers)
            
            # Add redirect relationships to graph
            if response.history:
                for resp in response.history:
                    self.attack_graph.add_edge(resp.url, url, relationship='redirect')
            
        except Exception as e:
            print(f"[ERROR] Failed to crawl {url}: {e}")
            self.attack_graph.add_node(url, type='page', status='error', error=str(e))

    def analyze_page_content(self, url, content, headers):
        """Analyze page content for potential vulnerabilities"""
        analysis = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'findings': []
        }
        
        # Check for sensitive information in content
        sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'[aA][pP][iI][_-]?[kK][eE][yY].*?[\'\"]([^\'\"]{10,50})[\'\"]',
            'password': r'[pP][aA][sS]{2}[wW][oO][rR][dD].*?[\'\"]([^\'\"]{3,50})[\'\"]',
        }
        
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                analysis['findings'].append({
                    'type': f'sensitive_{pattern_name}',
                    'matches': matches[:3]  # Limit to first 3 matches
                })
        
        # Check security headers
        security_headers = {
            'Content-Security-Policy': 'Missing CSP header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
        }
        
        for header, message in security_headers.items():
            if header not in headers:
                analysis['findings'].append({
                    'type': 'missing_security_header',
                    'header': header,
                    'message': message
                })
        
        # Check for comments containing sensitive info
        if '<!--' in content:
            comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
            for comment in comments:
                if any(keyword in comment.lower() for keyword in ['todo', 'fixme', 'password', 'key', 'secret']):
                    analysis['findings'].append({
                        'type': 'sensitive_comment',
                        'comment_preview': comment[:100] + '...' if len(comment) > 100 else comment
                    })
        
        if analysis['findings']:
            self.vulnerabilities.append(analysis)

    def worker(self):
        """Worker thread for crawling"""
        while True:
            try:
                url = self.to_crawl.get(timeout=10)
                self.crawl_page(url)
                self.visited_urls.add(url)
                self.to_crawl.task_done()
            except queue.Empty:
                break

    def start_crawling(self):
        """Start the crawling process"""
        print(f"[CRAWLER] Starting crawl of {self.base_url}")
        print(f"[CRAWLER] Max pages: {self.max_pages}, Max threads: {self.max_threads}")
        
        self.stats['start_time'] = datetime.now()
        
        # Check robots.txt
        robots_content = self.check_robots_txt()
        
        # Start worker threads
        threads = []
        for i in range(self.max_threads):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for crawling to complete
        self.to_crawl.join()
        
        self.stats['end_time'] = datetime.now()
        
        print(f"[CRAWLER] Crawling completed. Pages: {self.stats['pages_crawled']}")

class VulnerabilityScanner:
    def __init__(self, crawler):
        self.crawler = crawler
        self.session = crawler.session
        self.vulnerability_tests = []
        
        # Load payloads
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' AND 1=1--"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        self.command_injection_payloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../../../../etc/shadow"
        ]

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print("[SCAN] Testing for SQL Injection vulnerabilities...")
        
        for form in self.crawler.forms:
            for payload in self.sql_injection_payloads:
                try:
                    test_data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'password', 'search']:
                            test_data[input_field['name']] = payload
                        else:
                            test_data[input_field['name']] = input_field.get('value', '')
                    
                    if form['method'] == 'GET':
                        response = self.session.get(form['url'], params=test_data, timeout=10)
                    else:
                        response = self.session.post(form['url'], data=test_data, timeout=10)
                    
                    # Check for SQL error patterns
                    error_indicators = [
                        'sql syntax',
                        'mysql_fetch',
                        'ora-',
                        'microsoft odbc',
                        'postgresql',
                        'warning: mysql',
                        'unclosed quotation mark'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in error_indicators):
                        self.crawler.vulnerabilities.append({
                            'type': 'sql_injection',
                            'url': form['url'],
                            'form_method': form['method'],
                            'payload': payload,
                            'confidence': 'high',
                            'source_page': form['source_page']
                        })
                        print(f"  [SQLi] Potential SQL injection at {form['url']}")
                        break
                
                except Exception as e:
                    continue

    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print("[SCAN] Testing for XSS vulnerabilities...")
        
        for form in self.crawler.forms:
            for payload in self.xss_payloads:
                try:
                    test_data = {}
                    for input_field in form['inputs']:
                        if input_field['type'] in ['text', 'search', 'textarea']:
                            test_data[input_field['name']] = payload
                        else:
                            test_data[input_field['name']] = input_field.get('value', '')
                    
                    if form['method'] == 'GET':
                        response = self.session.get(form['url'], params=test_data, timeout=10)
                    else:
                        response = self.session.post(form['url'], data=test_data, timeout=10)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        self.crawler.vulnerabilities.append({
                            'type': 'xss',
                            'url': form['url'],
                            'form_method': form['method'],
                            'payload': payload,
                            'confidence': 'medium',
                            'source_page': form['source_page']
                        })
                        print(f"  [XSS] Potential XSS at {form['url']}")
                        break
                
                except Exception as e:
                    continue

    def test_path_traversal(self):
        """Test for path traversal vulnerabilities"""
        print("[SCAN] Testing for Path Traversal vulnerabilities...")
        
        # Test in URL parameters
        for url in self.crawler.visited_urls:
            if '?' in url:
                for payload in self.path_traversal_payloads:
                    try:
                        # Try appending payload to existing parameters
                        test_url = url + payload
                        response = self.session.get(test_url, timeout=10)
                        
                        # Check for successful file access indicators
                        if any(indicator in response.text.lower() for indicator in ['root:', 'bin/bash', 'etc/passwd', 'administrator']):
                            self.crawler.vulnerabilities.append({
                                'type': 'path_traversal',
                                'url': test_url,
                                'payload': payload,
                                'confidence': 'medium',
                                'source_page': url
                            })
                            print(f"  [PT] Potential path traversal at {url}")
                            break
                    
                    except Exception as e:
                        continue

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        print("[SCAN] Testing for Authentication Bypass vulnerabilities...")
        
        # Look for common authentication endpoints
        auth_endpoints = ['/admin', '/login', '/dashboard', '/cp', '/manager']
        
        for endpoint in auth_endpoints:
            test_url = self.crawler.base_url + endpoint
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check if we can access without authentication
                if response.status_code == 200 and not any(keyword in response.text.lower() 
                                                         for keyword in ['login', 'password', 'username', 'sign in']):
                    self.crawler.vulnerabilities.append({
                        'type': 'authentication_bypass',
                        'url': test_url,
                        'confidence': 'low',
                        'notes': 'Endpoint accessible without obvious authentication'
                    })
                    print(f"  [AUTH] Potential auth bypass at {test_url}")
            
            except Exception as e:
                continue

    def run_all_tests(self):
        """Run all vulnerability tests"""
        print("[SCANNER] Starting vulnerability assessment...")
        
        self.test_sql_injection()
        self.test_xss()
        self.test_path_traversal()
        self.test_authentication_bypass()
        
        print(f"[SCANNER] Vulnerability assessment completed. Found {len(self.crawler.vulnerabilities)} potential issues")

class AttackPathCorrelator:
    def __init__(self, crawler, scanner):
        self.crawler = crawler
        self.scanner = scanner
        self.attack_paths = []
        
    def build_attack_graph(self):
        """Build comprehensive attack graph"""
        print("[CORRELATOR] Building attack graph...")
        
        # Add vulnerability nodes and edges
        for vuln in self.crawler.vulnerabilities:
            vuln_id = f"vuln_{len(self.crawler.attack_graph.nodes)}"
            self.crawler.attack_graph.add_node(vuln_id, type='vulnerability', **vuln)
            
            # Connect vulnerability to its source page
            if 'source_page' in vuln:
                self.crawler.attack_graph.add_edge(vuln['source_page'], vuln_id, relationship='contains')
            
            # Connect vulnerability to target URL
            if 'url' in vuln:
                self.crawler.attack_graph.add_edge(vuln_id, vuln['url'], relationship='affects')
        
        # Add form relationships
        for form in self.crawler.forms:
            form_id = f"form_{len(self.crawler.attack_graph.nodes)}"
            self.crawler.attack_graph.add_node(form_id, type='form', **form)
            self.crawler.attack_graph.add_edge(form['source_page'], form_id, relationship='contains')
            self.crawler.attack_graph.add_edge(form_id, form['url'], relationship='submits_to')
    
    def find_attack_paths(self, start_url=None, target_goal="admin_access"):
        """Find potential attack paths through the application"""
        if start_url is None:
            start_url = self.crawler.base_url
        
        print(f"[CORRELATOR] Finding attack paths from {start_url} to {target_goal}...")
        
        # Simple BFS to find paths to sensitive areas
        sensitive_keywords = ['admin', 'dashboard', 'config', 'settings', 'user', 'profile']
        
        for node in self.crawler.attack_graph.nodes:
            node_data = self.crawler.attack_graph.nodes[node]
            
            # Check if node is a sensitive target
            if node_data.get('type') == 'page':
                url = node if isinstance(node, str) else node_data.get('url', '')
                if any(keyword in url.lower() for keyword in sensitive_keywords):
                    try:
                        # Find paths from start to this sensitive node
                        paths = nx.all_simple_paths(self.crawler.attack_graph, start_url, node, cutoff=5)
                        
                        for path in paths:
                            attack_path = {
                                'start': start_url,
                                'target': node,
                                'path': path,
                                'vulnerabilities': [],
                                'complexity': len(path),
                                'confidence': 'medium'
                            }
                            
                            # Find vulnerabilities along the path
                            for path_node in path:
                                node_info = self.crawler.attack_graph.nodes[path_node]
                                if node_info.get('type') == 'vulnerability':
                                    attack_path['vulnerabilities'].append({
                                        'node': path_node,
                                        'type': node_info.get('type'),
                                        'details': node_info
                                    })
                            
                            self.attack_paths.append(attack_path)
                    
                    except nx.NetworkXNoPath:
                        continue
        
        # Sort by number of vulnerabilities and path complexity
        self.attack_paths.sort(key=lambda x: (len(x['vulnerabilities']), -x['complexity']), reverse=True)
        
        print(f"[CORRELATOR] Found {len(self.attack_paths)} potential attack paths")
        
        return self.attack_paths
    
    def generate_attack_report(self):
        """Generate comprehensive attack path report"""
        report = {
            'scan_metadata': {
                'base_url': self.crawler.base_url,
                'crawl_time': self.crawler.stats,
                'total_vulnerabilities': len(self.crawler.vulnerabilities),
                'total_pages': self.crawler.stats['pages_crawled'],
                'generation_time': datetime.now().isoformat()
            },
            'vulnerabilities': self.crawler.vulnerabilities,
            'attack_paths': self.attack_paths,
            'risk_assessment': self.assess_overall_risk()
        }
        
        return report
    
    def assess_overall_risk(self):
        """Assess overall application risk"""
        risk_score = 0
        critical_vulns = 0
        high_vulns = 0
        medium_vulns = 0
        
        for vuln in self.crawler.vulnerabilities:
            if vuln.get('type') in ['sql_injection', 'authentication_bypass']:
                critical_vulns += 1
                risk_score += 10
            elif vuln.get('type') in ['xss', 'path_traversal']:
                high_vulns += 1
                risk_score += 7
            else:
                medium_vulns += 1
                risk_score += 3
        
        # Normalize risk score (0-100)
        risk_score = min(100, risk_score)
        
        risk_level = 'Low'
        if risk_score >= 70:
            risk_level = 'Critical'
        elif risk_score >= 50:
            risk_level = 'High'
        elif risk_score >= 30:
            risk_level = 'Medium'
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'medium_vulnerabilities': medium_vulns
        }

def main():
    parser = argparse.ArgumentParser(description='Web App Crawler + Vulnerability Correlator')
    parser.add_argument('url', help='Base URL to scan')
    parser.add_argument('--threads', type=int, default=10, help='Number of crawling threads')
    parser.add_argument('--max-pages', type=int, default=500, help='Maximum pages to crawl')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--no-scan', action='store_true', help='Skip vulnerability scanning')
    
    args = parser.parse_args()
    
    print("Web App Crawler + Vulnerability Correlator")
    print("=" * 50)
    
    # Initialize crawler
    crawler = WebAppCrawler(args.url, max_threads=args.threads, max_pages=args.max_pages)
    
    try:
        # Start crawling
        crawler.start_crawling()
        
        if not args.no_scan:
            # Run vulnerability scanner
            scanner = VulnerabilityScanner(crawler)
            scanner.run_all_tests()
        
        # Correlate attack paths
        correlator = AttackPathCorrelator(crawler, scanner if not args.no_scan else None)
        correlator.build_attack_graph()
        correlator.find_attack_paths()
        
        # Generate report
        report = correlator.generate_attack_report()
        
        # Save report
        output_file = args.output or f"web_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "=" * 50)
        print("SCAN SUMMARY")
        print("=" * 50)
        print(f"Base URL: {args.url}")
        print(f"Pages Crawled: {crawler.stats['pages_crawled']}")
        print(f"Forms Found: {crawler.stats['forms_found']}")
        print(f"Vulnerabilities Found: {len(crawler.vulnerabilities)}")
        print(f"Attack Paths Found: {len(correlator.attack_paths)}")
        print(f"Risk Level: {report['risk_assessment']['risk_level']}")
        print(f"Risk Score: {report['risk_assessment']['risk_score']}/100")
        print(f"Report Saved: {output_file}")
        
        # Show top attack paths
        if correlator.attack_paths:
            print("\nTOP ATTACK PATHS:")
            for i, path in enumerate(correlator.attack_paths[:3]):
                print(f"{i+1}. Path length: {path['complexity']}, Vulnerabilities: {len(path['vulnerabilities'])}")
                print(f"   Target: {path['target']}")
        
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")

if __name__ == "__main__":
    main()
