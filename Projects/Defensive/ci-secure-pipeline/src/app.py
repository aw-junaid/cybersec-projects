#!/usr/bin/env python3
"""
Secure CI/CD Pipeline Example Application
A simple web service demonstrating security best practices
"""

import os
import json
import logging
from flask import Flask, jsonify, request
import sys

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def hello():
    """Root endpoint returning service info"""
    return jsonify({
        'service': 'secure-ci-cd-demo',
        'version': '1.0.0',
        'status': 'healthy'
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'})

@app.route('/info')
def info():
    """System information endpoint"""
    return jsonify({
        'python_version': sys.version,
        'environment': os.getenv('ENVIRONMENT', 'development')
    })

def main():
    """Main application entry point"""
    port = int(os.getenv('PORT', 8080))
    debug = os.getenv('DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting secure CI/CD demo application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)

if __name__ == '__main__':
    main()
