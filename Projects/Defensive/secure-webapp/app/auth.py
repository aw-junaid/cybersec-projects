from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db, limiter
from app.models import User, AuditLog, Session
from app.security import SecurityUtils
import time

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = SecurityUtils.validate_input(request.form.get('username'), input_type='username')
        password = request.form.get('password')
        remember_me = bool(request.form.get('remember_me'))
        
        if not username or not password:
            flash('Please provide both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        # Security: Use constant-time comparison to prevent timing attacks
        valid_user = user is not None
        
        if valid_user:
            # Check if account is locked
            if user.is_locked():
                flash('Account temporarily locked due to too many failed attempts. Please try again later.', 'error')
                AuditLog.create_log(
                    user_id=user.id if user else None,
                    action='failed_login_locked',
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    details=f'Account locked until {user.locked_until}'
                )
                return render_template('login.html')
            
            # Verify password
            if user.check_password(password):
                # Successful login
                login_user(user, remember=remember_me)
                user.reset_failed_attempts()
                user.last_login = time.time()
                db.session.commit()
                
                # Create session record
                Session.create_session(
                    user.id,
                    request.remote_addr,
                    request.user_agent.string
                )
                
                # Log successful login
                AuditLog.create_log(
                    user_id=user.id,
                    action='login_success',
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                
                flash('Login successful!', 'success')
                
                # Safe redirect
                next_page = request.args.get('next')
                if next_page and SecurityUtils.is_safe_redirect(next_page):
                    return redirect(next_page)
                return redirect(url_for('main.dashboard'))
            else:
                # Failed login
                user.increment_failed_attempts()
        else:
            # Simulate password check to prevent timing attacks
            SecurityUtils.check_password('dummy_password', '$2b$12$dummyhashfordummycomparison')
        
        # Log failed attempt
        AuditLog.create_log(
            user_id=user.id if user else None,
            action='login_failed',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details=f'Username: {username}'
        )
        
        flash('Invalid username or password', 'error')
    
    # Generate CSRF token for login form
    csrf_token = SecurityUtils.generate_csrf_token()
    session['csrf_token'] = csrf_token
    
    return render_template('login.html', csrf_token=csrf_token)

@auth_bp.route('/logout')
@login_required
def logout():
    # Log logout action
    AuditLog.create_log(
        user_id=current_user.id,
        action='logout',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = SecurityUtils.validate_input(request.form.get('username'), input_type='username')
        email = SecurityUtils.validate_input(request.form.get('email'), input_type='email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        # Password strength validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        AuditLog.create_log(
            user_id=user.id,
            action='registration',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    csrf_token = SecurityUtils.generate_csrf_token()
    session['csrf_token'] = csrf_token
    
    return render_template('register.html', csrf_token=csrf_token)
