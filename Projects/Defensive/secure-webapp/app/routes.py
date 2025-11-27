from flask import Blueprint, render_template, request, jsonify, session
from flask_login import login_required, current_user
from app import db, limiter
from app.models import AuditLog
from app.security import SecurityUtils
import json

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@main_bp.route('/api/user/profile', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def update_profile():
    """Secure API endpoint for updating user profile"""
    # Verify CSRF token
    csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    # Validate and sanitize inputs
    email = SecurityUtils.validate_input(request.form.get('email'), input_type='email')
    display_name = SecurityUtils.validate_input(request.form.get('display_name'), max_length=100)
    
    if not email:
        return jsonify({'error': 'Invalid email address'}), 400
    
    # Check if email is already taken
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.id != current_user.id:
        return jsonify({'error': 'Email already registered'}), 400
    
    # Update user profile
    current_user.email = email
    if display_name:
        current_user.display_name = display_name
    
    db.session.commit()
    
    # Log profile update
    AuditLog.create_log(
        user_id=current_user.id,
        action='profile_update',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    
    return jsonify({'message': 'Profile updated successfully'})

@main_bp.route('/api/search')
@limiter.limit("20 per minute")
def search():
    """Secure search endpoint with input validation"""
    query = SecurityUtils.validate_input(request.args.get('q', ''), max_length=100)
    
    if not query:
        return jsonify({'error': 'Invalid search query'}), 400
    
    # Sanitize query for database (prevent SQL injection)
    # Using parameterized queries through ORM makes this safe
    
    # Log search activity
    if current_user.is_authenticated:
        AuditLog.create_log(
            user_id=current_user.id,
            action='search',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details=f'Query: {query}'
        )
    
    # Perform search (simplified)
    results = []  # Your search logic here
    
    return jsonify({'results': results, 'query': query})

@main_bp.route('/upload', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def upload_file():
    """Secure file upload endpoint"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file
    if not SecurityUtils.validate_file_upload(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    # Secure filename
    original_filename = SecurityUtils.validate_input(file.filename, max_length=255)
    secure_filename = f"upload_{current_user.id}_{SecurityUtils.generate_csrf_token()}.{original_filename.split('.')[-1]}"
    
    # Save file securely
    # file.save(os.path.join('uploads', secure_filename))
    
    # Log file upload
    AuditLog.create_log(
        user_id=current_user.id,
        action='file_upload',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details=f'Filename: {original_filename}'
    )
    
    return jsonify({'message': 'File uploaded successfully', 'filename': secure_filename})

# Error handlers
@main_bp.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@main_bp.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@main_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429
