import re
import html
from urllib.parse import urlparse
import bcrypt
import secrets
from flask import request, current_app
import bleach

class SecurityUtils:
    @staticmethod
    def hash_password(password):
        """Securely hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    @staticmethod
    def check_password(password, hashed):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    @staticmethod
    def generate_csrf_token():
        """Generate secure CSRF token"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_input(input_string, max_length=255, input_type='general'):
        """Validate and sanitize user input"""
        if not input_string or len(input_string) > max_length:
            return None
        
        # Remove null bytes
        input_string = input_string.replace('\x00', '')
        
        # Type-specific validation
        if input_type == 'email':
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_string):
                return None
            return input_string.lower()
        
        elif input_type == 'username':
            if not re.match(r'^[a-zA-Z0-9_-]{3,50}$', input_string):
                return None
            return input_string
        
        elif input_type == 'url':
            try:
                result = urlparse(input_string)
                if all([result.scheme, result.netloc]):
                    return input_string
                return None
            except:
                return None
        
        # General input sanitization
        sanitized = bleach.clean(
            input_string,
            tags=[],
            attributes=[],
            styles=[],
            strip=True
        )
        
        return sanitized
    
    @staticmethod
    def sanitize_html(html_content):
        """Sanitize HTML content to prevent XSS"""
        allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ul', 'ol', 'li']
        allowed_attributes = {}
        
        return bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            styles=[],
            strip=True
        )
    
    @staticmethod
    def validate_file_upload(filename, allowed_extensions=None, max_size=5*1024*1024):
        """Validate file uploads"""
        if allowed_extensions is None:
            allowed_extensions = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
        
        if '.' not in filename:
            return False
        
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in allowed_extensions:
            return False
        
        # Check content length
        if request.content_length > max_size:
            return False
        
        return True
    
    @staticmethod
    def is_safe_redirect(target):
        """Validate redirect URLs to prevent open redirects"""
        if not target:
            return False
        
        # Parse the URL
        parsed = urlparse(target)
        
        # Allow relative URLs
        if not parsed.netloc:
            return True
        
        # Check against allowed domains
        allowed_domains = ['example.com']  # Add your domains
        return parsed.netloc in allowed_domains

class SecurityHeaders:
    @staticmethod
    def set_security_headers(response):
        """Set security headers for all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Remove server header
        if 'Server' in response.headers:
            del response.headers['Server']
        
        return response
