from os import name
from flask import render_template, Flask, request, url_for, flash, redirect, Blueprint, session, jsonify, send_from_directory
from flask_mysqldb import MySQL 
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import uuid
import calendar
import math
import os
import re
import time
from werkzeug.utils import secure_filename
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta
import secrets






# Load environment variables
load_dotenv()

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire

# Session Security
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False') == 'True'
app.config['SESSION_COOKIE_HTTPONLY'] = os.getenv('SESSION_COOKIE_HTTPONLY', 'True') == 'True'
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
app.config['PERMANENT_SESSION_LIFETIME'] = int(os.getenv('PERMANENT_SESSION_LIFETIME', '3600'))

# Email Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '465'))
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True') == 'True'
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

# Database Configuration - MUST MATCH WEBSITE VARIABLE NAMES
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'ecommerce')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', '3306'))

# DEBUG: Print database config (password masked)
print("="*50)
print("DATABASE CONFIGURATION:")
print(f"MYSQL_HOST: {app.config['MYSQL_HOST']}")
print(f"MYSQL_PORT: {app.config['MYSQL_PORT']}")
print(f"MYSQL_USER: {app.config['MYSQL_USER']}")
print(f"MYSQL_DB: {app.config['MYSQL_DB']}")
print(f"MYSQL_PASSWORD: {'***SET***' if app.config['MYSQL_PASSWORD'] else '***EMPTY***'}")
print("="*50)

# Connection timeout for cloud databases
app.config['MYSQL_CONNECT_TIMEOUT'] = 30
# Note: Using default cursor (tuple-based) to match existing code that uses user[0], user[1], etc.

# SSL Configuration - Railway proxy connections DON'T need SSL
# Only enable if explicitly set to True in environment
if os.getenv('DB_SSL', 'False') == 'True':
    import ssl as ssl_module
    app.config['MYSQL_SSL'] = {
        'check_hostname': False,
        'verify_mode': ssl_module.CERT_NONE
    }
# Note: Railway's TCP proxy (*.proxy.rlwy.net) handles SSL internally
# External connections to Railway MySQL proxy should NOT use SSL

mysql = MySQL(app)

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Exempt API endpoints from CSRF (they use JSON and are protected by login_required)
@csrf.exempt
def csrf_exempt_api(f):
    return f

# Initialize Caching
# Use Redis in production for better performance and multi-server support
cache_config = {
    'CACHE_TYPE': os.getenv('CACHE_TYPE', 'SimpleCache'),  # SimpleCache for dev, RedisCache for prod
    'CACHE_DEFAULT_TIMEOUT': 300  # 5 minutes default
}

# If Redis URL is provided, use Redis
if os.getenv('REDIS_URL'):
    cache_config['CACHE_TYPE'] = 'RedisCache'
    cache_config['CACHE_REDIS_URL'] = os.getenv('REDIS_URL')

cache = Cache(app, config=cache_config)

# Initialize Rate Limiter
# Use Redis in production for distributed rate limiting
limiter_storage = os.getenv('RATELIMIT_STORAGE_URL', 'memory://')
if os.getenv('REDIS_URL') and limiter_storage == 'memory://':
    limiter_storage = os.getenv('REDIS_URL')

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=limiter_storage
)

# Security Headers with Talisman
# Relaxed CSP for development - tighten in production
csp = {
    'default-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
    'script-src': [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com",
        "https://unpkg.com",  # For Leaflet maps
        "https://*.tile.openstreetmap.org"
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://fonts.googleapis.com",
        "https://unpkg.com"  # For Leaflet CSS
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
    ],
    'img-src': [
        "'self'", 
        "data:", 
        "https:", 
        "blob:",
        "https://*.tile.openstreetmap.org",  # OpenStreetMap tiles
        "https://*.openstreetmap.org"
    ],
    'connect-src': [
        "'self'",
        "https://*.tile.openstreetmap.org",  # Map tile requests
        "https://nominatim.openstreetmap.org"  # Geocoding
    ],
    'frame-src': [
        "'self'",
        "https://www.google.com",  # If using Google Maps
        "https://maps.google.com"
    ]
}

talisman = Talisman(
    app,
    force_https=False,  # Set to True in production with HTTPS
    strict_transport_security=False,  # Disable HSTS in development
    content_security_policy=csp,
    content_security_policy_nonce_in=[],  # Disable nonce requirement
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'"
    }
)



PASSWORD_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

# List of disposable/temporary email domains to block
DISPOSABLE_EMAIL_DOMAINS = [
    'tempmail.com', 'guerrillamail.com', '10minutemail.com', 'throwaway.email',
    'temp-mail.org', 'fakeinbox.com', 'mailinator.com', 'yopmail.com',
    'trashmail.com', 'getnada.com', 'maildrop.cc', 'sharklasers.com'
]

def validate_email(email):
    """
    Comprehensive email validation
    Returns: (is_valid: bool, error_message: str)
    """
    if not email or not isinstance(email, str):
        return False, "Email is required"
    
    email = email.strip().lower()
    
    # Basic format validation
    if not EMAIL_REGEX.match(email):
        return False, "Invalid email format"
    
    # Check length
    if len(email) > 254:  # RFC 5321
        return False, "Email is too long"
    
    # Split into local and domain parts
    try:
        local, domain = email.rsplit('@', 1)
    except ValueError:
        return False, "Invalid email format"
    
    # Validate local part (before @)
    if len(local) > 64:  # RFC 5321
        return False, "Email local part is too long"
    
    if local.startswith('.') or local.endswith('.'):
        return False, "Email cannot start or end with a dot"
    
    if '..' in local:
        return False, "Email cannot contain consecutive dots"
    
    # Check for obvious fake/random emails
    import re
    
    # Reject emails that are too long (likely fake)
    if len(local) > 25:
        return False, "Email username is too long (max 25 characters)"
    
    # Check for repetitive patterns (e.g., "ririririir", "ababab")
    if re.search(r'(.{2,4})\1{3,}', local):
        return False, "Email appears to contain repetitive patterns"
    
    # Check for excessive consecutive consonants (fake emails)
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{7,}', local):
        return False, "Email appears to be invalid or randomly generated"
    
    # Check consonant/vowel ratio for longer emails
    if len(local) > 15:
        consonants = sum(1 for c in local if c in 'bcdfghjklmnpqrstvwxyz')
        vowels = sum(1 for c in local if c in 'aeiou')
        if vowels == 0 or consonants / vowels > 4:
            return False, "Email appears to be invalid or randomly generated"
    
    # Check for random-looking sequences (e.g., "ndagaswing")
    if len(local) > 18:
        # Count unique 2-character sequences
        bigrams = [local[i:i+2] for i in range(len(local)-1)]
        unique_ratio = len(set(bigrams)) / len(bigrams) if bigrams else 0
        if unique_ratio > 0.85:  # Too many unique patterns = random
            return False, "Email appears to be randomly generated"
    
    # Validate domain part
    if len(domain) < 4:  # Minimum: a.co
        return False, "Invalid email domain"
    
    # Check for disposable email domains
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        return False, "Temporary/disposable email addresses are not allowed"
    
    # Check if domain has valid TLD
    if '.' not in domain:
        return False, "Invalid email domain"
    
    tld = domain.split('.')[-1]
    if len(tld) < 2:
        return False, "Invalid email domain extension"
    
    # Verify domain exists (DNS check)
    try:
        import socket
        socket.gethostbyname(domain)
    except socket.gaierror:
        return False, f"Email domain '{domain}' does not exist"
    
    # SMTP Email Verification - Check if email can actually receive mail
    try:
        import smtplib
        import dns.resolver
        
        # Get MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_host = str(mx_records[0].exchange).rstrip('.')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False, f"Email domain '{domain}' cannot receive emails (no mail server)"
        except Exception:
            # If DNS check fails, continue with basic domain check
            mx_host = domain
        
        # Try to verify the email address with SMTP
        try:
            # Connect to mail server
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host)
            server.helo(server.local_hostname)
            server.mail('verify@yourdomain.com')  # Sender doesn't matter for RCPT check
            
            # Check if email address exists
            code, message = server.rcpt(email)
            server.quit()
            
            # 250 = mailbox exists, 251 = cannot verify but will forward
            if code not in [250, 251]:
                return False, f"Email address does not exist on mail server"
                
        except smtplib.SMTPServerDisconnected:
            # Server doesn't allow verification, but domain is valid
            pass
        except smtplib.SMTPConnectError:
            return False, f"Cannot connect to mail server for {domain}"
        except Exception as e:
            # If verification fails, we'll allow it (some servers block verification)
            pass
            
    except ImportError:
        # dnspython or smtplib not available, skip verification
        pass
    
    return True, None

# Login attempt tracking (in-memory, use Redis in production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

# Password reset code storage (in-memory, use Redis in production)
# Format: {email: {'code': '123456', 'expires': datetime, 'worker_id': 1}}
password_reset_codes = {}
RESET_CODE_EXPIRATION = timedelta(minutes=15)

def check_login_attempts(identifier):
    """Check if user is locked out due to too many failed attempts"""
    if identifier in login_attempts:
        attempts, lockout_until = login_attempts[identifier]
        if lockout_until and datetime.now() < lockout_until:
            remaining = (lockout_until - datetime.now()).seconds // 60
            return False, f"Account temporarily locked. Try again in {remaining} minutes."
        elif lockout_until and datetime.now() >= lockout_until:
            # Lockout expired, reset attempts
            del login_attempts[identifier]
    return True, None

def record_failed_attempt(identifier):
    """Record a failed login attempt"""
    if identifier not in login_attempts:
        login_attempts[identifier] = [1, None]
    else:
        attempts, _ = login_attempts[identifier]
        attempts += 1
        if attempts >= MAX_LOGIN_ATTEMPTS:
            lockout_until = datetime.now() + LOCKOUT_DURATION
            login_attempts[identifier] = [attempts, lockout_until]
        else:
            login_attempts[identifier] = [attempts, None]

def clear_login_attempts(identifier):
    """Clear login attempts after successful login"""
    if identifier in login_attempts:
        del login_attempts[identifier]

# ============= AUTHENTICATION DECORATORS =============
# Login required decorator - protects routes from unauthorized access
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # Redirect to login with next parameter (no flash here to avoid message on direct login visits)
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Page permission checker
def check_page_permission(page_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'worker_id' not in session:
                flash('Access denied', 'error')
                return redirect('/login')
            
            try:
                cur = mysql.connection.cursor()
                cur.execute("""
                    SELECT COUNT(*) FROM worker_page_permissions 
                    WHERE worker_id = %s AND pages = %s
                """, (session['worker_id'], page_name))
                has_permission = cur.fetchone()[0] > 0
                cur.close()
                
                if not has_permission:
                    flash(f'You do not have permission to access the {page_name} page', 'error')
                    return redirect('/access-denied')
                    
                return f(*args, **kwargs)
            except Exception as e:
                print(f"Permission check error: {e}")
                flash('Permission check failed', 'error')
                return redirect('/access-denied')
        return decorated_function
    return decorator

# Global inventory thresholds
LOW_STOCK_THRESHOLD = 10  # products with 1..10 units are considered low stock

# ============= PERFORMANCE & DATA MANAGEMENT HELPERS =============
def archive_old_orders(months_old=12):
    """
    Archive orders older than specified months to improve performance
    Call this monthly when you have 50,000+ orders
    """
    try:
        cur = mysql.connection.cursor()
        
        # Create archive table if not exists
        cur.execute("""
            CREATE TABLE IF NOT EXISTS orders_archive LIKE orders
        """)
        
        # Archive old orders
        cur.execute("""
            INSERT INTO orders_archive 
            SELECT * FROM orders 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL %s MONTH)
            AND id NOT IN (SELECT DISTINCT order_id FROM payments WHERE status = 'SUCCESSFUL')
        """, (months_old,))
        archived_count = cur.rowcount
        
        # Delete archived orders (be careful!)
        cur.execute("""
            DELETE FROM orders 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL %s MONTH)
            AND id NOT IN (SELECT DISTINCT order_id FROM payments WHERE status = 'SUCCESSFUL')
        """, (months_old,))
        deleted_count = cur.rowcount
        
        mysql.connection.commit()
        cur.close()
        
        return {'archived': archived_count, 'deleted': deleted_count}
    except Exception as e:
        mysql.connection.rollback()
        return {'error': str(e)}

def get_database_stats():
    """Get database performance statistics"""
    try:
        cur = mysql.connection.cursor()
        
        # Table sizes
        cur.execute("""
            SELECT table_name, table_rows, 
                   ROUND((data_length + index_length) / 1024 / 1024, 2) AS size_mb
            FROM information_schema.tables 
            WHERE table_schema = DATABASE()
            ORDER BY (data_length + index_length) DESC
        """)
        table_stats = cur.fetchall()
        
        cur.close()
        return {'tables': table_stats}
    except Exception as e:
        return {'error': str(e)}

# Order logic helper functions
def get_transaction_status(payment_status, delivered, provider):
    """
    Smart transaction status interpretation without database changes
    Returns: complete, partial, pending, cancelled
    """
    payment_status = (payment_status or '').lower().strip()
    delivered = (delivered or '').lower().strip() 
    provider = (provider or '').lower().strip()
    
    if payment_status == 'cancelled':
        return 'cancelled'
    
    money_received = payment_status == 'paid'
    goods_delivered = delivered in ('yes', 'y', 'true', '1', 'delivered')
    
    if provider in ('cod', 'none', ''):
        # COD: payment and delivery should happen together
        if money_received and goods_delivered:
            return 'complete'
        elif goods_delivered and not money_received:
            return 'partial'  # Delivered but not marked as paid (unusual)
        elif money_received and not goods_delivered:
            return 'partial'  # Paid but not delivered (cash collected, delivery pending)
        else:
            return 'pending'
    else:
        # Mobile Money: separate events
        if money_received and goods_delivered:
            return 'complete'
        elif money_received:
            return 'partial'  # Paid online, awaiting delivery
        elif goods_delivered:
            return 'partial'  # Delivered but payment not confirmed (unusual)
        else:
            return 'pending'

# Uploads configuration - SHARED with website
# Point to the website's images folder so both dashboard and website use the same images
WEBSITE_IMAGES_PATH = r'C:\Users\Public\Ecommerce website\static\images'
app.config['UPLOAD_FOLDER'] = WEBSITE_IMAGES_PATH
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

# Create the images folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def slugify(value: str) -> str:
    s = (value or '').lower().strip()
    s = re.sub(r"[^a-z0-9\-\s_]+", '', s)
    s = re.sub(r"[\s_]+", '-', s)
    s = re.sub(r"-+", '-', s)
    return s or 'image'

# Ensure a department is set so sidebar menus render
@app.before_request
def ensure_department():
    if 'department' not in session:
        session['department'] = 'admin'  # default for development/testing

@app.route('/api/payment-status')
def api_payment_status():
    """API endpoint to get payment status counts (Paid, Pending, Cancelled) with time filter"""
    try:
        period = request.args.get('period', 'all')  # 'today', '7days', 'month', 'all'
        print(f"DEBUG: Payment status requested for period: {period}")
        
        cur = mysql.connection.cursor()
        
        # Build date filter based on period
        date_filter = ""
        if period == 'today':
            date_filter = "AND DATE(o.created_at) = CURDATE()"
        elif period == '7days':
            date_filter = "AND o.created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
        elif period == 'month':
            date_filter = "AND MONTH(o.created_at) = MONTH(CURDATE()) AND YEAR(o.created_at) = YEAR(CURDATE())"
        
        print(f"DEBUG: Date filter: {date_filter}")
        
        # Get total orders with date filter
        query1 = f"SELECT COUNT(*) FROM orders o WHERE 1=1 {date_filter}"
        print(f"DEBUG: Query 1: {query1}")
        cur.execute(query1)
        total_orders = cur.fetchone()[0] or 0
        print(f"DEBUG: Total orders: {total_orders}")
        
        # Paid orders: only payment_status = 'paid'
        query2 = f"""
            SELECT COUNT(DISTINCT o.id) FROM orders o
            WHERE LOWER(TRIM(o.payment_status)) = 'paid'
            {date_filter}
        """
        print(f"DEBUG: Query 2: {query2}")
        cur.execute(query2)
        paid_count = cur.fetchone()[0] or 0
        print(f"DEBUG: Paid count: {paid_count}")
        
        # Cancelled orders: only payment_status = 'cancelled'
        query3 = f"""
            SELECT COUNT(DISTINCT o.id) FROM orders o
            WHERE LOWER(TRIM(o.payment_status)) = 'cancelled'
            {date_filter}
        """
        print(f"DEBUG: Query 3: {query3}")
        cur.execute(query3)
        cancelled_count = cur.fetchone()[0] or 0
        print(f"DEBUG: Cancelled count: {cancelled_count}")
        
        # Pending orders: payment_status = 'pending'
        query4 = f"""
            SELECT COUNT(DISTINCT o.id) FROM orders o
            WHERE LOWER(TRIM(o.payment_status)) = 'pending'
            {date_filter}
        """
        print(f"DEBUG: Query 4: {query4}")
        cur.execute(query4)
        pending_count = cur.fetchone()[0] or 0
        print(f"DEBUG: Pending count: {pending_count}")
        
        # Get revenue for paid orders
        query5 = f"""
            SELECT COALESCE(SUM(p.amount), 0) FROM payments p 
            JOIN orders o ON p.order_id = o.id
            WHERE p.status = 'SUCCESSFUL'
            AND LOWER(TRIM(o.payment_status)) = 'paid'
            {date_filter.replace('WHERE', 'AND')}
        """
        cur.execute(query5)
        paid_revenue = cur.fetchone()[0] or 0.0
        
        # Get total pending value
        query6 = f"""
            SELECT COALESCE(SUM(o.total_amount), 0) FROM orders o
            WHERE LOWER(TRIM(o.payment_status)) = 'pending'
            {date_filter}
        """
        cur.execute(query6)
        pending_revenue = cur.fetchone()[0] or 0.0
        
        # Get total cancelled value
        query7 = f"""
            SELECT COALESCE(SUM(o.total_amount), 0) FROM orders o
            WHERE LOWER(TRIM(o.payment_status)) = 'cancelled'
            {date_filter}
        """
        cur.execute(query7)
        cancelled_revenue = cur.fetchone()[0] or 0.0
        
        cur.close()
        
        result = {
            'ok': True,
            'paid': paid_count,
            'pending': pending_count,
            'cancelled': cancelled_count,
            'total': total_orders,
            'paid_revenue': float(paid_revenue),
            'pending_revenue': float(pending_revenue),
            'cancelled_revenue': float(cancelled_revenue)
        }
        print(f"DEBUG: Returning result: {result}")
        return jsonify(result)
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"ERROR in api_payment_status: {str(e)}")
        print(f"ERROR traceback: {error_trace}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/top-products')
def api_top_products():
    """API endpoint to get top 5 products by sales with time filter"""
    try:
        period = request.args.get('period', 'month')  # 'today', '7days', 'month', 'all'
        
        cur = mysql.connection.cursor()
        
        # Build date filter based on period
        date_filter = ""
        if period == 'today':
            date_filter = "AND DATE(o.created_at) = CURDATE()"
        elif period == '7days':
            date_filter = "AND o.created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
        elif period == 'month':
            date_filter = "AND MONTH(o.created_at) = MONTH(CURDATE()) AND YEAR(o.created_at) = YEAR(CURDATE())"
        
        # Get top 5 products
        cur.execute(f"""
            SELECT p.name, SUM(oi.quantity) as total_sold, SUM(oi.subtotal) as revenue
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            JOIN orders o ON oi.order_id = o.id
            WHERE LOWER(TRIM(o.payment_status)) = 'paid'
            {date_filter}
            GROUP BY p.id, p.name
            ORDER BY total_sold DESC
            LIMIT 5
        """)
        
        products = cur.fetchall()
        cur.close()
        
        # Format data
        result = []
        for product in products:
            result.append({
                'name': product[0],
                'quantity': int(product[1]) if product[1] else 0,
                'revenue': float(product[2]) if product[2] else 0.0
            })
        
        return jsonify({
            'ok': True,
            'products': result
        })
    except Exception as e:
        import traceback
        print(f"ERROR in api_top_products: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/orders/daily')
def api_daily_orders():
    """API endpoint to get daily order counts for a specific month/year"""
    try:
        month = request.args.get('month', type=int)
        year = request.args.get('year', type=int)
        
        if not month or not year:
            return jsonify({'ok': False, 'error': 'Month and year required'}), 400
        
        cur = mysql.connection.cursor()
        
        # Get daily order counts for the specified month
        cur.execute("""
            SELECT DAY(created_at) as day, COUNT(*) as order_count
            FROM orders
            WHERE MONTH(created_at) = %s AND YEAR(created_at) = %s
            GROUP BY DAY(created_at)
            ORDER BY day ASC
        """, (month, year))
        
        results = cur.fetchall()
        cur.close()
        
        # Create array for all days of the month (fill with 0 if no orders)
        import calendar
        days_in_month = calendar.monthrange(year, month)[1]
        daily_data = [0] * days_in_month
        
        for day, count in results:
            daily_data[day - 1] = count
        
        return jsonify({
            'ok': True,
            'days': list(range(1, days_in_month + 1)),
            'orders': daily_data
        })
    except Exception as e:
        import traceback
        print(f"ERROR in api_daily_orders: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/revenue/daily')
def api_daily_revenue():
    """API endpoint to fetch daily revenue for a specific month/year (includes both Mobile Money and COD)"""
    try:
        month = request.args.get('month', type=int)
        year = request.args.get('year', type=int)
        
        if not month or not year:
            return jsonify({'ok': False, 'error': 'Month and year required'}), 400
        
        cur = mysql.connection.cursor()
        
        # Get daily revenue combining both Mobile Money (payments table) and COD orders
        cur.execute("""
            SELECT DATE(revenue_date) as date, SUM(revenue_amount) as total_revenue
            FROM (
                -- Mobile Money payments (MTN, Airtel, etc.)
                SELECT DATE(created_at) as revenue_date, amount as revenue_amount
                FROM payments
                WHERE status = 'SUCCESSFUL'
                AND MONTH(created_at) = %s
                AND YEAR(created_at) = %s
                
                UNION ALL
                
                -- COD orders (paid on delivery)
                SELECT DATE(created_at) as revenue_date, total_amount as revenue_amount
                FROM orders
                WHERE (LOWER(TRIM(provider)) = 'none' OR LOWER(TRIM(provider)) = 'cod' OR provider IS NULL OR provider = '')
                AND LOWER(TRIM(delivered)) IN ('yes', 'y', 'true', '1')
                AND MONTH(created_at) = %s
                AND YEAR(created_at) = %s
                AND id NOT IN (SELECT DISTINCT order_id FROM payments WHERE status = 'SUCCESSFUL')
            ) AS combined_revenue
            GROUP BY DATE(revenue_date)
            ORDER BY date ASC
        """, (month, year, month, year))
        
        daily_data = cur.fetchall()
        cur.close()
        
        # Format data for JSON response
        result = []
        for date_obj, revenue in daily_data:
            result.append({
                'date': date_obj.strftime('%Y-%m-%d') if hasattr(date_obj, 'strftime') else str(date_obj),
                'revenue': float(revenue or 0)
            })
        
        return jsonify({'ok': True, 'data': result})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/database-stats')
@login_required
def api_database_stats():
    """API endpoint for database performance monitoring"""
    try:
        stats = get_database_stats()
        return jsonify({'ok': True, 'data': stats})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/archive-orders', methods=['POST'])
@login_required
def api_archive_orders():
    """API endpoint to archive old orders (use carefully!)"""
    try:
        months = request.json.get('months', 12)
        if months < 6:  # Safety check
            return jsonify({'ok': False, 'error': 'Minimum 6 months required'}), 400
        
        result = archive_old_orders(months)
        return jsonify({'ok': True, 'data': result})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/top-customers')
def api_top_customers():
    """API endpoint to get top customers by spending with time filter"""
    try:
        period = request.args.get('period', 'month')  # 'today', '7days', 'month', 'all'
        limit = request.args.get('limit', type=int, default=3)

        # Sanitize limit
        if not isinstance(limit, int) or limit <= 0:
            limit = 3
        limit = min(limit, 10)

        cur = mysql.connection.cursor()

        # Build date filters for orders and payments based on period
        order_date_filter = ""
        payment_date_filter = ""
        if period == 'today':
            order_date_filter = "AND DATE(o.created_at) = CURDATE()"
            payment_date_filter = "AND DATE(p.created_at) = CURDATE()"
        elif period == '7days':
            order_date_filter = "AND o.created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
            payment_date_filter = "AND p.created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)"
        elif period == 'month':
            order_date_filter = "AND MONTH(o.created_at) = MONTH(CURDATE()) AND YEAR(o.created_at) = YEAR(CURDATE())"
            payment_date_filter = "AND MONTH(p.created_at) = MONTH(CURDATE()) AND YEAR(p.created_at) = YEAR(CURDATE())"

        # Combined paid revenue per order: successful payments OR delivered COD orders with no successful payment
        query = f"""
            SELECT customer_name, SUM(total_amount) AS total_spent, COUNT(*) AS orders_count
            FROM (
                -- Orders paid via successful payments
                SELECT 
                    COALESCE(u.username, o.full_name, 'Guest') AS customer_name,
                    o.id AS order_id,
                    o.total_amount
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                WHERE o.id IN (
                    SELECT DISTINCT p.order_id
                    FROM payments p
                    WHERE p.status = 'SUCCESSFUL' {payment_date_filter}
                )
                {order_date_filter}

                UNION ALL

                -- COD orders delivered (no successful payment exists)
                SELECT 
                    COALESCE(u2.username, o2.full_name, 'Guest') AS customer_name,
                    o2.id AS order_id,
                    o2.total_amount
                FROM orders o2
                LEFT JOIN users u2 ON u2.id = o2.user_id
                WHERE (LOWER(TRIM(o2.provider)) IN ('none','cod','') OR o2.provider IS NULL)
                  AND LOWER(TRIM(o2.delivered)) IN ('yes','y','true','1')
                  {order_date_filter}
                  AND o2.id NOT IN (
                      SELECT DISTINCT p2.order_id FROM payments p2 WHERE p2.status = 'SUCCESSFUL' {payment_date_filter}
                  )
            ) AS paid_orders
            GROUP BY customer_name
            ORDER BY total_spent DESC
            LIMIT %s
        """

        cur.execute(query, (limit,))
        rows = cur.fetchall()
        cur.close()

        customers = [
            {
                'name': row[0] or 'Unknown',
                'total_spent': float(row[1] or 0),
                'orders_count': int(row[2] or 0),
            }
            for row in rows
        ]

        return jsonify({'ok': True, 'customers': customers})
    except Exception as e:
        import traceback
        print(f"ERROR in api_top_customers: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/')
@app.route('/dashboard')
@login_required
@check_page_permission('dashboard')
@cache.cached(timeout=60, key_prefix='dashboard_data')  # Cache for 1 minute
def dashboard():
    # Dashboard access (flash message removed for cleaner UX)
    
    try:
        cur = mysql.connection.cursor()
        
        # TEST: Check if we can query the database at all
        cur.execute("SELECT COUNT(*) FROM payments")
        test_count = cur.fetchone()[0]
        print(f"DEBUG: Total payments in database = {test_count}")
        
        # ROW 1: REVENUE CARDS
        # Total Revenue (all successful payments)
        cur.execute("""
            SELECT SUM(p.amount) FROM payments p 
            WHERE p.status = 'SUCCESSFUL'
        """)
        result = cur.fetchone()
        total_revenue = result[0] if result and result[0] is not None else 0.0
        print(f"DEBUG: Total Revenue Query Result = {result}, total_revenue = {total_revenue}")
        
        # DEBUG: Check what statuses exist
        cur.execute("SELECT DISTINCT status FROM payments")
        statuses = cur.fetchall()
        print(f"DEBUG: Payment statuses in database = {statuses}")
        
        # Monthly Orders (this month)
        cur.execute("""
            SELECT COUNT(*) FROM orders 
            WHERE MONTH(created_at) = MONTH(CURRENT_DATE()) 
            AND YEAR(created_at) = YEAR(CURRENT_DATE())
        """)
        monthly_orders = cur.fetchone()[0] or 0
        
        # Average Order Value (successful payments only)
        cur.execute("""
            SELECT AVG(p.amount) FROM payments p 
            WHERE p.status = 'SUCCESSFUL'
        """)
        average_order_value = cur.fetchone()[0] or 0.0
        
        # Revenue Growth (vs last month) — use the SAME combined logic as /api/revenue/daily
        # Combine: SUCCESSFUL payments + delivered COD orders that don't also have a successful payment (avoid double counts)
        # This month (combined)
        cur.execute("""
            SELECT SUM(revenue_amount) AS total_revenue
            FROM (
                -- Successful mobile money payments this month
                SELECT amount AS revenue_amount
                FROM payments
                WHERE status = 'SUCCESSFUL'
                AND MONTH(created_at) = MONTH(CURRENT_DATE())
                AND YEAR(created_at) = YEAR(CURRENT_DATE())
                
                UNION ALL
                
                -- COD orders delivered this month and not also paid via mobile money (to avoid double counting)
                SELECT o.total_amount AS revenue_amount
                FROM orders o
                WHERE (LOWER(TRIM(o.provider)) = 'none' OR LOWER(TRIM(o.provider)) = 'cod' OR o.provider IS NULL OR o.provider = '')
                AND LOWER(TRIM(o.delivered)) IN ('yes','y','true','1')
                AND MONTH(o.created_at) = MONTH(CURRENT_DATE())
                AND YEAR(o.created_at) = YEAR(CURRENT_DATE())
                AND o.id NOT IN (
                    SELECT DISTINCT order_id FROM payments
                    WHERE status = 'SUCCESSFUL'
                    AND MONTH(created_at) = MONTH(CURRENT_DATE())
                    AND YEAR(created_at) = YEAR(CURRENT_DATE())
                )
            ) AS combined
        """)
        this_month_revenue = cur.fetchone()[0] or 0.0
        
        # Last month (combined)
        cur.execute("""
            SELECT SUM(revenue_amount) AS total_revenue
            FROM (
                -- Successful mobile money payments last month
                SELECT amount AS revenue_amount
                FROM payments
                WHERE status = 'SUCCESSFUL'
                AND MONTH(created_at) = MONTH(DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
                AND YEAR(created_at) = YEAR(DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
                
                UNION ALL
                
                -- COD orders delivered last month and not also paid via mobile money
                SELECT o.total_amount AS revenue_amount
                FROM orders o
                WHERE (LOWER(TRIM(o.provider)) = 'none' OR LOWER(TRIM(o.provider)) = 'cod' OR o.provider IS NULL OR o.provider = '')
                AND LOWER(TRIM(o.delivered)) IN ('yes','y','true','1')
                AND MONTH(o.created_at) = MONTH(DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
                AND YEAR(o.created_at) = YEAR(DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
                AND o.id NOT IN (
                    SELECT DISTINCT order_id FROM payments
                    WHERE status = 'SUCCESSFUL'
                    AND MONTH(created_at) = MONTH(DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
                    AND YEAR(created_at) = YEAR(DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH))
                )
            ) AS combined
        """)
        last_month_revenue = cur.fetchone()[0] or 0.0
        
        if last_month_revenue > 0:
            revenue_growth = ((this_month_revenue - last_month_revenue) / last_month_revenue) * 100
        else:
            revenue_growth = 0.0 if this_month_revenue == 0 else 100.0
        
        # ROW 2: CHARTS
        # Payment Status Counts
        cur.execute("""
            SELECT status, COUNT(*) as count 
            FROM payments 
            GROUP BY status
        """)
        payment_status_data = cur.fetchall()
        payment_status_counts = {
            'successful': 0,
            'failed': 0,
            'pending': 0
        }
        for status, count in payment_status_data:
            status_lower = (status or '').lower()
            if status_lower in payment_status_counts:
                payment_status_counts[status_lower] = count
        
        # Top 5 Categories by Revenue (using payments for successful orders)
        cur.execute("""
            SELECT c.name, SUM(oi.quantity * oi.price) as revenue
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            JOIN categories c ON p.category_id = c.id
            JOIN payments pay ON oi.order_id = pay.order_id
            WHERE pay.status = 'SUCCESSFUL'
            GROUP BY c.name
            ORDER BY revenue DESC
            LIMIT 5
        """)
        top_category_revenue = cur.fetchall()
        
        # ROW 3: CHARTS & ALERTS
        # Daily Revenue (last 30 days from successful payments)
        cur.execute("""
            SELECT DATE(created_at) as date, SUM(amount) as revenue
            FROM payments
            WHERE status = 'SUCCESSFUL'
            AND created_at >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """)
        daily_revenue = cur.fetchall()
        
        # Out of Stock and Low Stock Items
        cur.execute("""
            SELECT name, stock, price 
            FROM products 
            WHERE stock >= 0 AND stock <= %s
            ORDER BY stock ASC
            LIMIT 10
        """, (LOW_STOCK_THRESHOLD,))
        low_stock_items = cur.fetchall()
        
        # Top 5 Products by Sales (quantity sold) - This Month by default for page load
        cur.execute("""
            SELECT p.name, SUM(oi.quantity) as total_sold, SUM(oi.subtotal) as revenue
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            JOIN orders o ON oi.order_id = o.id
            WHERE LOWER(TRIM(o.payment_status)) = 'paid'
            AND MONTH(o.created_at) = MONTH(CURDATE()) AND YEAR(o.created_at) = YEAR(CURDATE())
            GROUP BY p.id, p.name
            ORDER BY total_sold DESC
            LIMIT 5
        """)
        top_products_by_sales = cur.fetchall()
        
        # ROW 4: TABLE & HEALTH CARDS
        # Recent Transactions (last 10 orders with payment info)
        cur.execute("""
            SELECT o.id, o.full_name as customer_name, o.total_amount, 
                   o.delivered as order_status, 
                   COALESCE(p.status, 'PENDING') as payment_status, o.created_at
            FROM orders o
            LEFT JOIN payments p ON o.id = p.order_id
            ORDER BY o.created_at DESC
            LIMIT 10
        """)
        recent_orders = cur.fetchall()
        print(f"DEBUG: Recent orders count = {len(recent_orders)}")
        
        # Health Cards Data
        # Conversion Rate (successful payments / total orders)
        cur.execute("SELECT COUNT(*) FROM orders")
        total_orders_count = cur.fetchone()[0] or 0
        cur.execute("SELECT COUNT(DISTINCT order_id) FROM payments WHERE status = 'SUCCESSFUL'")
        successful_orders_count = cur.fetchone()[0] or 0
        conversion_rate = (successful_orders_count / total_orders_count * 100) if total_orders_count > 0 else 0.0
        
        # Failed Payments Percentage
        cur.execute("SELECT COUNT(*) FROM payments WHERE status = 'FAILED'")
        failed_payments = cur.fetchone()[0] or 0
        cur.execute("SELECT COUNT(*) FROM payments")
        total_payments = cur.fetchone()[0] or 0
        failed_payments_percent = (failed_payments / total_payments * 100) if total_payments > 0 else 0.0
        
        # Average Stock Level
        cur.execute("SELECT AVG(stock) FROM products")
        average_stock_level = cur.fetchone()[0] or 0.0
        
        # Repeat Customers (customers with > 1 order)
        cur.execute("""
            SELECT COUNT(DISTINCT user_id) FROM orders 
            WHERE user_id IS NOT NULL 
            AND user_id IN (
                SELECT user_id FROM orders WHERE user_id IS NOT NULL GROUP BY user_id HAVING COUNT(*) > 1
            )
        """)
        repeat_customers_count = cur.fetchone()[0] or 0
        
        # Total Products
        cur.execute("SELECT COUNT(*) FROM products")
        total_products = cur.fetchone()[0] or 0
        
        # Active Categories
        cur.execute("SELECT COUNT(DISTINCT category_id) FROM products WHERE category_id IS NOT NULL")
        active_categories = cur.fetchone()[0] or 0
        
        # Monthly Revenue (this month only - for metric card) — use combined revenue to match the chart
        monthly_revenue = this_month_revenue
        
        # Pending Orders Count (orders with payment_status = 'pending')
        cur.execute("""
            SELECT COUNT(*) FROM orders 
            WHERE LOWER(TRIM(delivered)) = 'no'
        """)
        pending_orders_count = cur.fetchone()[0] or 0
        
        # TODAY's metrics
        # Today's Revenue
        cur.execute("""
            SELECT COALESCE(SUM(p.amount), 0) FROM payments p 
            WHERE p.status = 'SUCCESSFUL'
            AND DATE(p.created_at) = CURDATE()
        """)
        today_revenue = cur.fetchone()[0] or 0.0
        
        # Today's Orders Count
        cur.execute("""
            SELECT COUNT(*) FROM orders 
            WHERE DATE(created_at) = CURDATE()
        """)
        today_orders = cur.fetchone()[0] or 0
        
        # Today's Average Order Value
        if today_orders > 0:
            today_avg_order_value = today_revenue / today_orders
        else:
            today_avg_order_value = 0.0
        
        cur.close()
        
        return render_template("dashboard.html",
            total_revenue=total_revenue,
            monthly_orders=monthly_orders,
            average_order_value=average_order_value,
            revenue_growth=revenue_growth,
            payment_status_counts=payment_status_counts,
            top_category_revenue=top_category_revenue,
            daily_revenue=daily_revenue,
            low_stock_items=low_stock_items,
            low_stock_count=len(low_stock_items),
            recent_orders=recent_orders,
            conversion_rate=conversion_rate,
            failed_payments_percent=failed_payments_percent,
            average_stock_level=average_stock_level,
            repeat_customers_count=repeat_customers_count,
            total_products=total_products,
            active_categories=active_categories,
            monthly_revenue=monthly_revenue,
            pending_orders_count=pending_orders_count,
            today_revenue=today_revenue,
            today_orders=today_orders,
            today_avg_order_value=today_avg_order_value,
            top_products_by_sales=top_products_by_sales
        )
    except Exception as e:
        print(f"Dashboard error: {e}")
        # Return with default values to avoid template errors
        return render_template("dashboard.html",
            error=str(e),
            total_revenue=0.0,
            monthly_orders=0,
            average_order_value=0.0,
            revenue_growth=0.0,
            payment_status_counts={'successful': 0, 'failed': 0, 'pending': 0},
            top_category_revenue=[],
            daily_revenue=[],
            low_stock_items=[],
            low_stock_count=0,
            recent_orders=[],
            conversion_rate=0.0,
            failed_payments_percent=0.0,
            average_stock_level=0.0,
            repeat_customers_count=0,
            total_products=0,
            active_categories=0,
            monthly_revenue=0.0,
            pending_orders_count=0,
            today_revenue=0.0,
            today_orders=0,
            today_avg_order_value=0.0,
            top_products_by_sales=[]
        )

@app.route('/orders')
@login_required
@check_page_permission('orders')
def orders():
    # Orders page access (flash message removed for cleaner UX)
    
    # Read filters from query params
    q = request.args.get('q', type=str, default='').strip()
    status = request.args.get('status', '').lower()
    delivered_filter = request.args.get('delivered', '').lower()
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    sort = request.args.get('sort', 'newest')
    stock_filter = request.args.get('stock', '')

    # Build query dynamically but safely
    where = []
    params = []
    
    # EXCLUDE delivered and cancelled orders by default (they go to archives)
    where.append("NOT (LOWER(TRIM(COALESCE(delivered, ''))) IN ('yes', 'y', 'true', '1') OR LOWER(TRIM(COALESCE(delivered, ''))) = 'false')")
    
    if q:
        where.append("(CAST(id AS CHAR) LIKE %s OR full_name LIKE %s)")
        like = f"%{q}%"
        params.extend([like, like])
    if status:
        where.append("LOWER(status) = %s")
        params.append(status)
    # Filter options (if user specifically wants to see archived orders on orders page)
    if delivered_filter in ('delivered','not_delivered','cancelled'):
        # Remove the default exclusion filter
        where = [w for w in where if 'NOT (' not in w]
        if delivered_filter == 'delivered':
            where.append("LOWER(TRIM(COALESCE(delivered, ''))) IN ('yes', 'y', 'true', '1')")
        elif delivered_filter == 'not_delivered':
            where.append("LOWER(TRIM(COALESCE(delivered, ''))) IN ('no', 'n', 'false', '0', '')")
        elif delivered_filter == 'cancelled':
            where.append("LOWER(TRIM(COALESCE(delivered, ''))) = 'false')")
    if date_from:
        where.append("DATE(created_at) >= %s")
        params.append(date_from)
    if date_to:
        where.append("DATE(created_at) <= %s")
        params.append(date_to)

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    order_sql = " ORDER BY created_at DESC" if sort == 'newest' else " ORDER BY created_at ASC"

    # Enhanced Pagination for Large Datasets
    per_page = 20  # Increased from 9 for better performance
    try:
        LOW_STOCK_THRESHOLD = 10
        page = int(request.args.get('page', 1))
        if page < 1: page = 1
        
        # Cursor-based pagination for better performance on large datasets
        cursor_id = request.args.get('cursor')
        if cursor_id and sort == 'newest':
            # Use cursor for "next page" navigation (more efficient than OFFSET)
            where.append("id < %s")
            params.append(int(cursor_id))
        elif cursor_id and sort == 'oldest':
            where.append("id > %s") 
            params.append(int(cursor_id))
            
    except Exception:
        page = 1
        cursor_id = None
    
    # Traditional offset for first page or when cursor not available
    offset = (page - 1) * per_page if not cursor_id else 0

    # Fetch orders (paged)
    cur = mysql.connection.cursor()
    # Detect optional columns once
    cur.execute("SHOW COLUMNS FROM orders LIKE 'notes'")
    has_notes_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'address_line'")
    has_address_line_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'city'")
    has_city_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'payment_status'")
    has_payment_status_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'status'")
    has_status_col = cur.fetchone() is not None
    # Build dynamic SELECT with optional columns
    select_fields = "id, full_name, created_at, total_amount"
    if has_status_col:
        select_fields += ", status"
    select_fields += ", delivery_phone, provider, delivered"
    if has_payment_status_col:
        select_fields += ", payment_status"
    
    # Optimized query - avoid OFFSET for cursor-based pagination
    if cursor_id:
        cur.execute(
            f"""
            SELECT {select_fields}
            FROM orders
            {where_sql}
            {order_sql}
            LIMIT %s
            """, params + [per_page],
        )
    else:
        # Traditional pagination for first page or when cursor not available
        cur.execute(
            f"""
            SELECT {select_fields}
            FROM orders
            {where_sql}
            {order_sql}
            LIMIT %s OFFSET %s
            """, params + [per_page, offset],
        )
    rows = cur.fetchall()

    # Normalize rows (cursor returns tuples by default)
    orders_list = []
    for r in rows:
        # Unpack based on which columns exist
        idx = 0
        oid = r[idx]; idx += 1
        full_name = r[idx]; idx += 1
        created_at = r[idx]; idx += 1
        total_amount = r[idx]; idx += 1
        
        if has_status_col:
            st = r[idx]; idx += 1
        else:
            st = 'pending'  # Default status
            
        phone = r[idx]; idx += 1
        provider = r[idx]; idx += 1
        delivered = r[idx]; idx += 1
        
        if has_payment_status_col:
            payment_status = r[idx]; idx += 1
        else:
            payment_status = 'pending'  # Default value if column doesn't exist
            
        # Determine payment status - respect database value for cancelled orders
        provider_lower = (provider or '').lower().strip()
        delivered_lower = (delivered or '').lower().strip()
        delivered_truthy = delivered_lower in ('yes', 'y', 'true', '1', 'delivered')
        
        # Check if order/payment is explicitly cancelled
        order_status_lower = (st or '').lower().strip()
        db_payment_status_lower = (payment_status or '').lower().strip()
        
        if order_status_lower == 'cancelled' or db_payment_status_lower == 'cancelled' or delivered_lower == 'false':
            # Respect cancelled status from database
            final_payment_status = 'cancelled'
        else:
            # Auto-determine payment status for non-cancelled orders
            if provider_lower in ('none', ''):
                # No provider - only paid when delivered (becomes COD)
                final_payment_status = 'paid' if delivered_truthy else 'pending'
            elif provider_lower == 'cod':
                # COD orders are paid when delivered
                final_payment_status = 'paid' if delivered_truthy else 'pending'
            else:
                # Any known provider (MTN, AIRTEL, etc.) means already paid
                final_payment_status = 'paid'
        
        item = {
            'id': oid,
            'code': f"ORD-{oid}",
            'customer': full_name or '—',
            'date': created_at.strftime('%Y-%m-%d') if hasattr(created_at, 'strftime') else str(created_at),
            'total': float(total_amount) if total_amount is not None else 0.0,
            'status': st or 'pending',
            'phone': phone or '',
            'provider': provider or '',
            'delivered': delivered or '',
            'payment_status': final_payment_status,
        }
        if has_notes_col or has_address_line_col or has_city_col:
            select_bits = []
            if has_notes_col:
                select_bits.append('notes')
            if has_address_line_col:
                select_bits.append('address_line')
            if has_city_col:
                select_bits.append('city')
            if select_bits:
                q2 = f"SELECT {', '.join(select_bits)} FROM orders WHERE id=%s LIMIT 1"
                cur.execute(q2, (oid,))
                extra = cur.fetchone()
                if extra is not None:
                    idx = 0
                    if has_notes_col:
                        item['notes'] = (extra[idx] or '').strip() if extra[idx] is not None else ''
                        idx += 1
                    if has_address_line_col:
                        item['address_line'] = (extra[idx] or '').strip() if extra[idx] is not None else ''
                        idx += 1
                    if has_city_col:
                        item['city'] = (extra[idx] or '').strip() if extra[idx] is not None else ''
        orders_list.append(item)

    # Optimized stats with single query for better performance
    # Combined query reduces database round trips from 4 to 2
    cur.execute(f"""
        SELECT 
            COUNT(*) as total_rows,
            SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as todays_count,
            SUM(CASE WHEN DATE(created_at) = CURDATE() THEN total_amount ELSE 0 END) as todays_revenue,
            SUM(CASE WHEN DATE(created_at) = CURDATE() AND LOWER(TRIM(COALESCE(delivered, ''))) IN ('no', 'n', 'false', '0', '') THEN 1 ELSE 0 END) as not_delivered_count,
            SUM(CASE WHEN DATE(created_at) = CURDATE() AND LOWER(TRIM(COALESCE(delivered, ''))) IN ('yes', 'y', 'true', '1') THEN 1 ELSE 0 END) as delivered_count
        FROM orders{where_sql}
    """, params)
    stats_row = cur.fetchone()
    total_rows = stats_row[0] or 0
    todays_count = stats_row[1] or 0
    todays_revenue = stats_row[2] or 0.0
    not_delivered_count = stats_row[3] or 0
    delivered_count = stats_row[4] or 0

    # Compute today's COGS (if schema supports it) and net profit = revenue - COGS
    # Detect required columns first
    cur.execute("SHOW COLUMNS FROM order_items LIKE 'product_id'")
    has_oi_product = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM products LIKE 'cost_of_goods'")
    has_prod_cogs = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM order_items LIKE 'quantity'")
    has_qty = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM order_items LIKE 'qty'")
    has_qty_alt = cur.fetchone() is not None

    todays_cogs = 0.0
    if has_oi_product and has_prod_cogs and (has_qty or has_qty_alt):
        # Build a safe quantity expression only using existing columns
        if has_qty and has_qty_alt:
            qty_expr = "COALESCE(oi.quantity, oi.qty, 1)"
        elif has_qty:
            qty_expr = "COALESCE(oi.quantity, 1)"
        elif has_qty_alt:
            qty_expr = "COALESCE(oi.qty, 1)"
        else:
            qty_expr = "1"
        cur.execute(
            f"""
            SELECT COALESCE(SUM(COALESCE(p.cost_of_goods,0) * {qty_expr}), 0)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            LEFT JOIN products p ON p.id = oi.product_id
            WHERE DATE(o.created_at) = CURDATE()
            """
        )
        row = cur.fetchone()
        todays_cogs = float(row[0] or 0)
    todays_revenue = float(todays_revenue or 0)
    todays_net_profit = max(todays_revenue - todays_cogs, 0.0)
    cur.close()

    def fmt_money(v):
        try:
            return f"RWF {v:,.2f}".replace(",","_").replace(".",",").replace("_"," ") if False else f"RWF {v:,.0f}" if v == int(v) else f"RWF {v:,.2f}"
        except Exception:
            return f"RWF {v}"

    response = render_template(
        "orders.html",
        orders=orders_list,
        stats={
            'todays_orders': todays_count,
            'not_delivered': not_delivered_count,
            'delivered': delivered_count,
            'todays_revenue': fmt_money(float(todays_revenue)),
            'todays_cogs': fmt_money(float(todays_cogs)),
            'todays_net_profit': fmt_money(float(todays_net_profit)),
        },
        filters={
            'q': q,
            'status': status or '',
            'delivered': delivered_filter or '',
            'from': date_from or '',
            'to': date_to or '',
            'sort': sort,
        },
        pagination={
            'page': page,
            'per_page': per_page,
            'total': total_rows,
            'pages': math.ceil(total_rows / per_page) if per_page else 1,
        }
    )
    
    return response

@app.route('/archives')
@login_required
@check_page_permission('orders')
def archives():
    """Archives page - shows delivered and cancelled orders"""
    
    # Read filters from query params
    q = request.args.get('q', type=str, default='').strip()
    date_from = request.args.get('from')
    date_to = request.args.get('to')
    sort = request.args.get('sort', 'newest')

    # Build query - include delivered OR cancelled orders
    where = ["(LOWER(TRIM(COALESCE(delivered, ''))) IN ('yes', 'y', 'true', '1') OR LOWER(TRIM(COALESCE(delivered, ''))) = 'false')"]
    params = []
    
    if q:
        where.append("(CAST(id AS CHAR) LIKE %s OR full_name LIKE %s)")
        like = f"%{q}%"
        params.extend([like, like])
    
    if date_from:
        where.append("DATE(created_at) >= %s")
        params.append(date_from)
    if date_to:
        where.append("DATE(created_at) <= %s")
        params.append(date_to)

    where_sql = " WHERE " + " AND ".join(where)
    order_sql = " ORDER BY created_at DESC" if sort == 'newest' else " ORDER BY created_at ASC"

    # Pagination
    per_page = 20
    try:
        page = int(request.args.get('page', 1))
        if page < 1: page = 1
    except Exception:
        page = 1
    
    offset = (page - 1) * per_page

    # Fetch delivered orders (paged)
    cur = mysql.connection.cursor()
    
    # Detect optional columns
    cur.execute("SHOW COLUMNS FROM orders LIKE 'notes'")
    has_notes_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'address_line'")
    has_address_line_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'city'")
    has_city_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'payment_status'")
    has_payment_status_col = cur.fetchone() is not None
    cur.execute("SHOW COLUMNS FROM orders LIKE 'status'")
    has_status_col = cur.fetchone() is not None
    
    # Build dynamic SELECT
    select_fields = "id, full_name, created_at, total_amount"
    if has_status_col:
        select_fields += ", status"
    select_fields += ", delivery_phone, provider, delivered"
    if has_payment_status_col:
        select_fields += ", payment_status"
    
    cur.execute(
        f"""
        SELECT {select_fields}
        FROM orders
        {where_sql}
        {order_sql}
        LIMIT %s OFFSET %s
        """, params + [per_page, offset],
    )
    rows = cur.fetchall()

    # Normalize rows
    orders_list = []
    for r in rows:
        idx = 0
        oid = r[idx]; idx += 1
        full_name = r[idx]; idx += 1
        created_at = r[idx]; idx += 1
        total_amount = r[idx]; idx += 1
        
        if has_status_col:
            st = r[idx]; idx += 1
        else:
            st = 'pending'
            
        phone = r[idx]; idx += 1
        provider = r[idx]; idx += 1
        delivered = r[idx]; idx += 1
        
        if has_payment_status_col:
            payment_status = r[idx]; idx += 1
        else:
            payment_status = 'pending'
            
        provider_lower = (provider or '').lower().strip()
        delivered_lower = (delivered or '').lower().strip()
        
        # Determine payment status for archived orders
        if delivered_lower == 'false':
            final_payment_status = 'cancelled'
        elif delivered_lower in ('yes', 'y', 'true', '1'):
            final_payment_status = 'paid'
        else:
            final_payment_status = payment_status or 'pending'
        
        item = {
            'id': oid,
            'code': f"ORD-{oid}",
            'customer': full_name or '—',
            'date': created_at.strftime('%Y-%m-%d') if hasattr(created_at, 'strftime') else str(created_at),
            'total': float(total_amount) if total_amount is not None else 0.0,
            'status': st or 'delivered',
            'phone': phone or '',
            'provider': provider or '',
            'delivered': delivered or '',
            'payment_status': final_payment_status,
        }
        
        if has_notes_col or has_address_line_col or has_city_col:
            select_bits = []
            if has_notes_col:
                select_bits.append('notes')
            if has_address_line_col:
                select_bits.append('address_line')
            if has_city_col:
                select_bits.append('city')
            if select_bits:
                q2 = f"SELECT {', '.join(select_bits)} FROM orders WHERE id=%s LIMIT 1"
                cur.execute(q2, (oid,))
                extra = cur.fetchone()
                if extra is not None:
                    idx = 0
                    if has_notes_col:
                        item['notes'] = (extra[idx] or '').strip() if extra[idx] is not None else ''
                        idx += 1
                    if has_address_line_col:
                        item['address_line'] = (extra[idx] or '').strip() if extra[idx] is not None else ''
                        idx += 1
                    if has_city_col:
                        item['city'] = (extra[idx] or '').strip() if extra[idx] is not None else ''
        orders_list.append(item)

    # Get stats for archived orders (delivered + cancelled)
    cur.execute(f"""
        SELECT 
            COUNT(*) as total_rows,
            SUM(CASE WHEN LOWER(TRIM(COALESCE(delivered, ''))) IN ('yes', 'y', 'true', '1') THEN total_amount ELSE 0 END) as delivered_revenue,
            SUM(CASE WHEN LOWER(TRIM(COALESCE(delivered, ''))) IN ('yes', 'y', 'true', '1') THEN 1 ELSE 0 END) as delivered_count,
            SUM(CASE WHEN LOWER(TRIM(COALESCE(delivered, ''))) = 'false' THEN 1 ELSE 0 END) as cancelled_count,
            MIN(created_at) as first_date,
            MAX(created_at) as last_date
        FROM orders{where_sql}
    """, params)
    stats_row = cur.fetchone()
    total_rows = stats_row[0] or 0
    delivered_revenue = float(stats_row[1] or 0)
    delivered_count = stats_row[2] or 0
    cancelled_count = stats_row[3] or 0
    first_date = stats_row[4]
    last_date = stats_row[5]
    
    cur.close()

    def fmt_money(v):
        try:
            return f"RWF {v:,.2f}".replace(",","_").replace(".",",").replace("_"," ") if False else f"RWF {v:,.0f}" if v == int(v) else f"RWF {v:,.2f}"
        except Exception:
            return f"RWF {v}"

    response = render_template(
        "archives.html",
        orders=orders_list,
        stats={
            'total_archived': total_rows,
            'delivered_count': delivered_count,
            'cancelled_count': cancelled_count,
            'total_revenue': fmt_money(delivered_revenue),
            'first_date': first_date.strftime('%Y-%m-%d') if first_date and hasattr(first_date, 'strftime') else '',
            'last_date': last_date.strftime('%Y-%m-%d') if last_date and hasattr(last_date, 'strftime') else '',
        },
        filters={
            'q': q,
            'from': date_from or '',
            'to': date_to or '',
            'sort': sort,
        },
        pagination={
            'page': page,
            'per_page': per_page,
            'total': total_rows,
            'pages': math.ceil(total_rows / per_page) if per_page else 1,
        }
    )
    
    return response

# ---------------------- Category APIs ----------------------
@app.route('/api/categories/create', methods=['POST'])
@csrf.exempt
def api_create_category():
    try:
        payload = request.get_json(force=True) or {}
        name = (payload.get('name') or '').strip()
        if not name:
            return jsonify({'ok': False, 'error': 'Category name is required'}), 400
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO categories (name) VALUES (%s)", (name,))
        cid = cur.lastrowid
        mysql.connection.commit()
        cur.close()
        return jsonify({'ok': True, 'id': int(cid), 'name': name})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(e)}), 500

# Set admin reply on a review
@app.route('/api/reviews/reply', methods=['POST'])
@csrf.exempt
def api_reply_review():
    try:
        data = request.get_json(force=True, silent=True) or {}
        rid = data.get('id')
        uid = data.get('user_id')
        pid = data.get('product_id')
        rating = data.get('rating')
        body = data.get('review') or data.get('comment') or ''
        reply_text = (data.get('reply') or '').strip()
        if uid is None or pid is None or reply_text == '':
            return jsonify({'ok': False, 'error': 'user_id, product_id and reply required'}), 400
        cur = mysql.connection.cursor()
        # pick reply column name
        def has_col(tbl, col):
            cur.execute(f"SHOW COLUMNS FROM {tbl} LIKE %s", (col,))
            return cur.fetchone() is not None
        reply_col = None
        for cand in ['replies','reply','replie','admin_reply']:
            if has_col('reviews', cand):
                reply_col = cand
                break
        if not reply_col:
            cur.close()
            return jsonify({'ok': False, 'error': 'No reply column in reviews table'}), 500

        # Build WHERE similar to delete
        wh = ["user_id = %s", "product_id = %s"]
        params = [uid, pid]
        if rating is not None:
            wh.append("COALESCE(rating,0) = %s")
            params.append(int(rating))
        if body:
            text_cols = []
            if has_col('reviews','review'): text_cols.append('review')
            if has_col('reviews','comment'): text_cols.append('comment')
            if has_col('reviews','content'): text_cols.append('content')
            if text_cols:
                if len(text_cols) == 1 and text_cols[0] == 'review':
                    wh.append("review = %s")
                    params.append(body)
                else:
                    wh.append("COALESCE(" + ", ".join(text_cols + ["''"]) + ") = %s")
                    params.append(body)
        if rid is not None:
            wh.append("id = %s")
            params.append(int(rid))

        sql = f"UPDATE reviews SET {reply_col} = %s WHERE " + " AND ".join(wh) + " LIMIT 1"
        cur.execute(sql, [reply_text] + params)
        mysql.connection.commit()
        updated = cur.rowcount
        cur.close()
        
        # Flash success message for review reply
        if updated > 0:
            flash('Review reply added successfully!', 'success')
        else:
            flash('Review not found or no changes made', 'warning')
        
        return jsonify({'ok': True, 'updated': int(updated)})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(e)}), 500

# Create/submit a new review (for customers on ecommerce site)
@app.route('/api/reviews', methods=['POST'])
@csrf.exempt
def api_create_review():
    try:
        data = request.get_json(force=True, silent=True) or {}
        user_id = data.get('user_id')
        product_id = data.get('product_id')
        rating = data.get('rating')
        review_text = (data.get('review') or data.get('comment') or '').strip()
        
        # Validation
        if not user_id or not product_id:
            return jsonify({'ok': False, 'error': 'user_id and product_id are required'}), 400
        if not rating or not (1 <= int(rating) <= 5):
            return jsonify({'ok': False, 'error': 'rating must be between 1 and 5'}), 400
        if not review_text:
            return jsonify({'ok': False, 'error': 'review text is required'}), 400
        
        cur = mysql.connection.cursor()
        
        # Check if user exists
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'ok': False, 'error': 'User not found'}), 404
        
        # Check if product exists
        cur.execute("SELECT id FROM products WHERE id = %s", (product_id,))
        if not cur.fetchone():
            cur.close()
            return jsonify({'ok': False, 'error': 'Product not found'}), 404
        
        # Check if user already reviewed this product
        cur.execute("SELECT id FROM reviews WHERE user_id = %s AND product_id = %s", (user_id, product_id))
        if cur.fetchone():
            cur.close()
            return jsonify({'ok': False, 'error': 'You have already reviewed this product'}), 400
        
        # Insert the review
        cur.execute(
            "INSERT INTO reviews (user_id, product_id, rating, review, replie) VALUES (%s, %s, %s, %s, '')",
            (user_id, product_id, rating, review_text)
        )
        mysql.connection.commit()
        review_id = cur.lastrowid
        
        # Update product rating
        cur.execute("""
            UPDATE products 
            SET rate = (SELECT AVG(rating) FROM reviews WHERE product_id = %s)
            WHERE id = %s
        """, (product_id, product_id))
        mysql.connection.commit()
        cur.close()
        
        return jsonify({'ok': True, 'review_id': review_id, 'message': 'Review submitted successfully!'})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/categories/delete', methods=['POST'])
@csrf.exempt
def api_delete_category():
    try:
        payload = request.get_json(force=True) or {}
        cid = payload.get('id')
        if not cid:
            return jsonify({'ok': False, 'error': 'Category id is required'}), 400
        cid = int(cid)
        cur = mysql.connection.cursor()
        # Detach products first to avoid FK failures if any
        try:
            cur.execute("UPDATE products SET category_id = NULL WHERE category_id = %s", (cid,))
        except Exception:
            pass
        cur.execute("DELETE FROM categories WHERE id = %s", (cid,))
        mysql.connection.commit()
        cur.close()
        return jsonify({'ok': True})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(e)}), 500
@app.route('/api/customers/delete', methods=['POST'])
@csrf.exempt
def api_delete_customer():
    try:
        data = request.get_json(silent=True) or {}
        user_id = data.get('user_id')
        if not user_id:
            return jsonify({'ok': False, 'error': 'user_id is required'}), 400
        cur = mysql.connection.cursor()
        try:
            # Get customer name for flash message
            cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
            customer = cur.fetchone()
            customer_name = customer[0] if customer else f"Customer #{user_id}"
            
            cur.execute("UPDATE orders SET user_id = NULL WHERE user_id = %s", (user_id,))
            orders_detached = cur.rowcount or 0
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            users_deleted = cur.rowcount or 0
            mysql.connection.commit()
            
            # Flash success message for customer deletion
            if users_deleted > 0:
                flash(f'Customer "{customer_name}" deleted successfully! {orders_detached} orders detached.', 'success')
            else:
                flash(f'Customer not found', 'error')
            
            return jsonify({'ok': True, 'orders_detached': orders_detached, 'users_deleted': users_deleted})
        finally:
            try:
                cur.close()
            except Exception:
                pass
    except Exception as e:
        flash(f'Error deleting customer: {str(e)}', 'error')
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/customers/send-email', methods=['POST'])
@csrf.exempt
@login_required
@check_page_permission('customers')
def send_email_to_customer():
    """Send custom email to a customer"""
    try:
        data = request.get_json()
        customer_email = data.get('customer_email')
        customer_name = data.get('customer_name')
        subject = data.get('subject')
        message = data.get('message')
        
        if not all([customer_email, subject, message]):
            return jsonify({'ok': False, 'error': 'Missing required fields'}), 400
        
        # Get sender name from session
        sender_name = session.get('name', 'Dashboard Admin')
        
        # Send email
        msg = Message(
            subject=subject,
            recipients=[customer_email],
            sender=('Dashboard Team', app.config['MAIL_USERNAME'])
        )
        
        # Create email HTML with table-based layout for Gmail compatibility
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
                <tr>
                    <td align="center" style="padding: 40px 20px;">
                        <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                            <!-- Header -->
                            <tr>
                                <td style="background-color: #228B22; padding: 30px; text-align: center;">
                                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">{subject}</h1>
                                </td>
                            </tr>
                            
                            <!-- Content -->
                            <tr>
                                <td style="padding: 40px;">
                                    <p style="margin: 0 0 16px 0; color: #555555; font-size: 15px; line-height: 1.6;">Hello <strong>{customer_name or 'Valued Customer'}</strong>,</p>
                                    <div style="color: #555555; font-size: 15px; line-height: 1.8; white-space: pre-wrap;">{message}</div>
                                    
                                    <p style="margin: 32px 0 0 0; color: #555555; font-size: 15px; line-height: 1.6;">
                                        Best regards,<br><strong style="color: #228B22;">{sender_name}</strong>
                                    </p>
                                </td>
                            </tr>
                            
                            <!-- Footer -->
                            <tr>
                                <td style="background-color: #f8f9fa; padding: 24px; text-align: center; border-top: 1px solid #e0e0e0;">
                                    <p style="margin: 0 0 8px 0; color: #888888; font-size: 13px;">This email was sent from Dashboard.</p>
                                    <p style="margin: 0; color: #888888; font-size: 13px;">&copy; 2025 Dashboard. All rights reserved.</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        mail.send(msg)
        print(f"Custom email sent to customer: {customer_email}")
        
        return jsonify({'ok': True, 'message': 'Email sent successfully'})
    except Exception as e:
        print(f"Send customer email error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500


# Lightweight APIs used by Orders page modals
@app.route('/api/orders/<int:oid>/items')
@login_required
def api_order_items(oid: int):
    try:
        cur = mysql.connection.cursor()
        
        # Check if status column exists
        cur.execute("SHOW COLUMNS FROM orders LIKE 'status'")
        has_status_col = cur.fetchone() is not None
        
        # Build dynamic SELECT query
        if has_status_col:
            cur.execute(
                "SELECT id, full_name, total_amount, status, created_at, delivered FROM orders WHERE id=%s LIMIT 1",
                (oid,)
            )
            order_row = cur.fetchone()
            if not order_row:
                cur.close()
                return jsonify({"ok": False, "error": "Order not found"}), 404
            order_info = {
                "id": order_row[0],
                "full_name": order_row[1],
                "total": float(order_row[2]) if order_row[2] is not None else 0.0,
                "status": (order_row[3] or '').strip(),
                "date": order_row[4].strftime('%Y-%m-%d') if hasattr(order_row[4], 'strftime') else str(order_row[4]),
                "delivered": (order_row[5] or '').strip(),
            }
        else:
            cur.execute(
                "SELECT id, full_name, total_amount, created_at, delivered FROM orders WHERE id=%s LIMIT 1",
                (oid,)
            )
            order_row = cur.fetchone()
            if not order_row:
                cur.close()
                return jsonify({"ok": False, "error": "Order not found"}), 404
            order_info = {
                "id": order_row[0],
                "full_name": order_row[1],
                "total": float(order_row[2]) if order_row[2] is not None else 0.0,
                "status": "pending",  # Default status
                "date": order_row[3].strftime('%Y-%m-%d') if hasattr(order_row[3], 'strftime') else str(order_row[3]),
                "delivered": (order_row[4] or '').strip(),
            }
        # Just use the stored prices from order_items - they are already final prices after discount
        items = []
        computed_total = 0.0
        cur.execute(
            """
            SELECT product_name, price, quantity, VARIATIONS
            FROM order_items
            WHERE order_id=%s
            ORDER BY id ASC
            """,
            (oid,)
        )
        rows = cur.fetchall()
        for name, price, qty, variations in rows:
            price_f = float(price or 0)
            qty_i = int(qty or 0)
            subtotal = price_f * qty_i
            computed_total += subtotal
            items.append({
                "name": name,
                "price": price_f,
                "qty": qty_i,
                "subtotal": subtotal,
                "variations": variations or "",
            })

        # Added charges from orders table: delivery + tax
        subtotal = round(computed_total, 2)
        # Detect possible columns
        cur.execute("SHOW COLUMNS FROM orders LIKE 'delivery_fee'")
        has_delivery_fee = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM orders LIKE 'shipping_fee'")
        has_shipping_fee = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM orders LIKE 'tax_percent'")
        has_tax_percent = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM orders LIKE 'tax_rate'")
        has_tax_rate = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM orders LIKE 'tax_amount'")
        has_tax_amount = cur.fetchone() is not None

        # Defaults if not stored in DB
        DEFAULT_DELIVERY = 1500.0
        DEFAULT_TAX_PERCENT = 18.0

        delivery_fee = DEFAULT_DELIVERY
        if has_delivery_fee:
            cur.execute("SELECT delivery_fee FROM orders WHERE id=%s", (oid,))
            row = cur.fetchone()
            delivery_fee = float(row[0]) if row and row[0] is not None else DEFAULT_DELIVERY
        elif has_shipping_fee:
            cur.execute("SELECT shipping_fee FROM orders WHERE id=%s", (oid,))
            row = cur.fetchone()
            delivery_fee = float(row[0]) if row and row[0] is not None else DEFAULT_DELIVERY

        tax_percent = DEFAULT_TAX_PERCENT
        tax_amount = 0.0
        if has_tax_amount:
            cur.execute("SELECT tax_amount FROM orders WHERE id=%s", (oid,))
            row = cur.fetchone()
            tax_amount = float(row[0]) if row and row[0] is not None else subtotal * (DEFAULT_TAX_PERCENT/100.0)
        else:
            if has_tax_percent:
                cur.execute("SELECT tax_percent FROM orders WHERE id=%s", (oid,))
                row = cur.fetchone()
                tax_percent = float(row[0]) if row and row[0] is not None else DEFAULT_TAX_PERCENT
            elif has_tax_rate:
                cur.execute("SELECT tax_rate FROM orders WHERE id=%s", (oid,))
                row = cur.fetchone()
                tax_percent = float(row[0]) if row and row[0] is not None else DEFAULT_TAX_PERCENT
            tax_amount = subtotal * (tax_percent / 100.0)

        grand_total = subtotal + delivery_fee + tax_amount
        order_info["subtotal"] = subtotal
        order_info["delivery_fee"] = round(delivery_fee, 2)
        order_info["tax_percent"] = round(tax_percent, 2)
        order_info["tax_amount"] = round(tax_amount, 2)
        order_info["total"] = round(grand_total, 2)
        cur.close()
        return jsonify({"ok": True, "order": order_info, "items": items})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/products/create', methods=['POST'])
@csrf.exempt
def api_create_product():
    try:
        payload = request.get_json(force=True) or {}
        name = (payload.get('name') or '').strip()
        price = float(payload.get('price') or 0)
        image = (payload.get('image') or '').strip()
        category_id = payload.get('category_id')
        category_id = int(category_id) if category_id not in (None, '', 'null') else None
        stock = int(payload.get('stock') or 0)
        description = (payload.get('description') or '').strip()
        discount = float(payload.get('discount') or 0)
        cost_of_goods = payload.get('cost_of_goods')
        cost_of_goods = float(cost_of_goods) if cost_of_goods not in (None, '', 'null') else None

        if not name:
            return jsonify({"ok": False, "error": "name is required"}), 400

        cur = mysql.connection.cursor()
        # Discover available columns to keep this robust across schemas
        cur.execute("SHOW COLUMNS FROM products")
        cols = {row[0].lower() for row in (cur.fetchall() or [])}

        insert_cols = []
        values = []
        placeholders = []

        def add(col, val):
            insert_cols.append(col)
            values.append(val)
            placeholders.append('%s')

        if 'name' in cols: add('name', name)
        if 'price' in cols: add('price', price)
        if 'stock' in cols: add('stock', stock)
        if 'image' in cols: add('image', image)
        if 'description' in cols: add('description', description)
        if 'discount' in cols: add('discount', discount)
        if 'category_id' in cols: add('category_id', category_id)
        if 'cost_of_goods' in cols: add('cost_of_goods', cost_of_goods)

        if not insert_cols:
            return jsonify({"ok": False, "error": "No compatible columns found on products table"}), 500

        sql = f"INSERT INTO products ({', '.join(insert_cols)}) VALUES ({', '.join(placeholders)})"
        cur.execute(sql, tuple(values))
        new_id = cur.lastrowid
        mysql.connection.commit()
        cur.close()
        
        # Flash success message for product creation
        flash(f'Product "{name}" created successfully!', 'success')
        
        return jsonify({"ok": True, "id": int(new_id) if new_id else None})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/products/<int:pid>/delete', methods=['POST'])
@csrf.exempt
def api_delete_product(pid: int):
    try:
        cur = mysql.connection.cursor()
        # Ensure product exists and get name for flash message
        cur.execute("SELECT id, name FROM products WHERE id=%s", (pid,))
        product = cur.fetchone()
        if not product:
            cur.close()
            flash(f'Product #{pid} not found', 'error')
            return jsonify({"ok": False, "error": "Product not found"}), 404
        
        product_name = product[1] or f"Product #{pid}"
        
        # Attempt delete
        cur.execute("DELETE FROM products WHERE id=%s", (pid,))
        mysql.connection.commit()
        cur.close()
        
        # Flash success message for product deletion
        flash(f'Product "{product_name}" deleted successfully!', 'success')
        
        return jsonify({"ok": True})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/orders/<int:oid>/location')
@login_required
def api_order_location(oid: int):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT id, full_name, address_line, city, latitude, longitude FROM orders WHERE id=%s LIMIT 1",
        (oid,)
    )
    row = cur.fetchone()
    cur.close()
    if not row:
        return jsonify({"ok": False, "error": "Order not found"}), 404
    lat = None if row[4] is None else float(row[4])
    lon = None if row[5] is None else float(row[5])
    return jsonify({
        "ok": True,
        "order": {
            "id": row[0],
            "full_name": row[1],
            "address": row[2],
            "city": row[3],
            "lat": lat,
            "lon": lon,
        }
    })

# Helper function to parse variations and update stock
def update_stock_for_order(cur, oid, operation='add'):
    """
    Update stock based on order items and their variations.
    operation: 'add' when cancelling orders or marking as not delivered
    Note: Stock is NOT updated when marking orders as delivered
    
    IMPORTANT: Safely handles deleted products - logs warnings but continues processing.
    Products deleted after order placement cannot have stock restored.
    """
    # Fetch all order items for this order
    cur.execute("""
        SELECT product_id, quantity, VARIATIONS
        FROM order_items
        WHERE order_id=%s AND product_id IS NOT NULL
    """, (oid,))
    
    order_items = cur.fetchall()
    
    for product_id, quantity, variations_str in order_items:
        # SAFETY CHECK: Verify product still exists before attempting stock operations
        cur.execute("SELECT id, name FROM products WHERE id = %s", (product_id,))
        product_row = cur.fetchone()
        
        if not product_row:
            # Product was deleted - log the issue but continue with other items
            print(f"WARNING: Cannot restore stock for deleted product ID {product_id} (quantity: {quantity})")
            continue  # Skip this item - cannot restore stock for deleted products
        
        # Parse variations string: e.g., "color:Black, size:40" or "color:Black" or ""
        variations_str = (variations_str or '').strip()
        
        if not variations_str:
            # No variations - update product stock directly
            if operation == 'subtract':
                cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (quantity, product_id))
            else:  # add
                cur.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (quantity, product_id))
            continue
        
        # Parse variations into dict
        variations = {}
        for part in variations_str.split(','):
            part = part.strip()
            if ':' in part:
                key, val = part.split(':', 1)
                variations[key.strip().lower()] = val.strip()
        
        # Determine which variations we have
        has_image_var = 'color' in variations or 'style' in variations
        has_dropdown_var = 'size' in variations or any(k not in ['color', 'style'] for k in variations.keys())
        
        # Extract variation names
        image_var_name = variations.get('color') or variations.get('style')
        dropdown_attr_name = None
        dropdown_attr_value = None
        
        # Find dropdown variation (typically 'size')
        for key in variations:
            if key not in ['color', 'style']:
                dropdown_attr_name = key.capitalize()  # 'Size', 'Material', etc.
                dropdown_attr_value = variations[key]
                break
        
        # CASE 1: Only image variations (color or style)
        if has_image_var and not has_dropdown_var and image_var_name:
            # Find the image variation ID
            cur.execute("""
                SELECT id FROM image_variations
                WHERE prod_id = %s AND name = %s
                LIMIT 1
            """, (product_id, image_var_name))
            img_var = cur.fetchone()
            
            if img_var:
                img_var_id = img_var[0]
                if operation == 'subtract':
                    cur.execute("UPDATE image_variations SET stock = stock - %s WHERE id = %s", (quantity, img_var_id))
                else:  # add
                    cur.execute("UPDATE image_variations SET stock = stock + %s WHERE id = %s", (quantity, img_var_id))
                # Product stock will be updated by trigger
            else:
                # Variation not found - update product stock directly
                if operation == 'subtract':
                    cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (quantity, product_id))
                else:  # add
                    cur.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (quantity, product_id))
        
        # CASE 2: Both dropdown and image variations
        elif has_image_var and has_dropdown_var and image_var_name and dropdown_attr_name and dropdown_attr_value:
            # Find the image variation ID first
            cur.execute("""
                SELECT id FROM image_variations
                WHERE prod_id = %s AND name = %s
                LIMIT 1
            """, (product_id, image_var_name))
            img_var = cur.fetchone()
            
            if img_var:
                img_var_id = img_var[0]
                
                # Find the dropdown variation linked to this image variation
                cur.execute("""
                    SELECT id FROM dropdown_variation
                    WHERE prod_id = %s AND img_var_id = %s 
                    AND attr_name = %s AND attr_value = %s
                    LIMIT 1
                """, (product_id, img_var_id, dropdown_attr_name, dropdown_attr_value))
                dropdown_var = cur.fetchone()
                
                if dropdown_var:
                    dropdown_var_id = dropdown_var[0]
                    if operation == 'subtract':
                        cur.execute("UPDATE dropdown_variation SET stock = stock - %s WHERE id = %s", (quantity, dropdown_var_id))
                    else:  # add
                        cur.execute("UPDATE dropdown_variation SET stock = stock + %s WHERE id = %s", (quantity, dropdown_var_id))
                    # Triggers will update image_variations.stock and products.stock
                else:
                    # Dropdown variation not found - update product stock directly
                    if operation == 'subtract':
                        cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (quantity, product_id))
                    else:  # add
                        cur.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (quantity, product_id))
            else:
                # Image variation not found - update product stock directly
                if operation == 'subtract':
                    cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (quantity, product_id))
                else:  # add
                    cur.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (quantity, product_id))
        
        # CASE 3: Only dropdown variations (rare but possible)
        elif not has_image_var and has_dropdown_var and dropdown_attr_name and dropdown_attr_value:
            # Find dropdown variation without image link
            cur.execute("""
                SELECT id FROM dropdown_variation
                WHERE prod_id = %s AND attr_name = %s AND attr_value = %s
                AND (img_var_id IS NULL OR img_var_id = 0)
                LIMIT 1
            """, (product_id, dropdown_attr_name, dropdown_attr_value))
            dropdown_var = cur.fetchone()
            
            if dropdown_var:
                dropdown_var_id = dropdown_var[0]
                if operation == 'subtract':
                    cur.execute("UPDATE dropdown_variation SET stock = stock - %s WHERE id = %s", (quantity, dropdown_var_id))
                else:  # add
                    cur.execute("UPDATE dropdown_variation SET stock = stock + %s WHERE id = %s", (quantity, dropdown_var_id))
                # Triggers will update products.stock
            else:
                # Dropdown variation not found - update product stock directly
                if operation == 'subtract':
                    cur.execute("UPDATE products SET stock = stock - %s WHERE id = %s", (quantity, product_id))
                else:  # add
                    cur.execute("UPDATE products SET stock = stock + %s WHERE id = %s", (quantity, product_id))


# Update delivered status
@app.route('/api/orders/<int:oid>/delivered', methods=['POST'])
@csrf.exempt
@login_required
def api_order_set_delivered(oid: int):
    """
    Update order delivery status with proper validation and transactions
    """
    try:
        # Validate input
        payload = request.get_json(silent=True) or {}
        value = payload.get('value', '').lower().strip()
        if value not in ('yes', 'no'):
            return jsonify({"ok": False, "error": "value must be 'yes' or 'no'"}), 400
        
        cur = mysql.connection.cursor()
        
        # START TRANSACTION
        mysql.connection.begin()
        
        try:
            # Get current order info with validation
            cur.execute("""
                SELECT provider, delivered, status, payment_status 
                FROM orders 
                WHERE id = %s
            """, (oid,))
            order_row = cur.fetchone()
            
            if not order_row:
                mysql.connection.rollback()
                return jsonify({"ok": False, "error": "Order not found"}), 404
            
            provider, previous_delivered, order_status, current_payment_status = order_row
            
            # Validate order state transitions
            order_status = (order_status or '').lower().strip()
            if order_status == 'cancelled':
                mysql.connection.rollback()
                return jsonify({"ok": False, "error": "Cannot update delivery status of cancelled orders"}), 400
            
            # Normalize values
            provider = (provider or '').lower().strip()
            previous_delivered = (previous_delivered or '').lower().strip()
            current_payment_status = (current_payment_status or '').lower().strip()
            
            delivered_truthy = value == 'yes'
            previous_delivered_truthy = previous_delivered in ('yes', 'y', 'true', '1', 'delivered')
            
            # Validate business logic
            if delivered_truthy == previous_delivered_truthy:
                mysql.connection.rollback()
                return jsonify({"ok": False, "error": f"Order is already {'delivered' if delivered_truthy else 'not delivered'}"}), 400
            
            # Update delivered status
            cur.execute("UPDATE orders SET delivered = %s WHERE id = %s", (value, oid))
            
            # Update payment status based on business rules
            new_payment_status = current_payment_status
            new_provider = provider
            
            if provider in ('none', '', None):
                if delivered_truthy:  # Marking as delivered
                    new_provider = 'cod'
                    new_payment_status = 'paid'
                else:  # Marking as not delivered
                    new_payment_status = 'pending'
            elif provider == 'cod':
                if delivered_truthy:  # COD delivered = paid
                    new_payment_status = 'paid'
                else:  # COD not delivered = pending
                    new_payment_status = 'pending'
            # For other providers (MTN, Airtel, etc.), payment status doesn't change with delivery
            
            # Update provider and payment_status if changed
            if new_provider != provider or new_payment_status != current_payment_status:
                cur.execute("""
                    UPDATE orders 
                    SET provider = %s, payment_status = %s 
                    WHERE id = %s
                """, (new_provider.upper() if new_provider else new_provider, new_payment_status, oid))
            
            # COMMIT TRANSACTION
            mysql.connection.commit()
            
            # Flash message for successful operation
            if delivered_truthy:
                flash(f'Order #{oid} marked as delivered and moved to Archives!', 'success')
                message = "Order marked as delivered and moved to Archives"
            else:
                flash(f'Order #{oid} marked as not delivered successfully!', 'success')
                message = "Order marked as not delivered successfully"
            
            return jsonify({
                "ok": True, 
                "delivered": value,
                "payment_status": new_payment_status,
                "provider": new_provider,
                "message": message
            })
            
        except Exception as inner_e:
            mysql.connection.rollback()
            raise inner_e
            
        finally:
            cur.close()
            
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": f"Failed to update delivery status: {str(e)}"}), 500

# Cancel order with proper validation and error handling
@app.route('/api/orders/<int:oid>/cancel', methods=['POST'])
@csrf.exempt
@login_required
def api_order_cancel(oid: int):
    """
    Cancel an order with proper validation, stock management, and transaction handling
    """
    try:
        cur = mysql.connection.cursor()
        
        # START TRANSACTION
        mysql.connection.begin()
        
        try:
            # Get current order status with full validation
            cur.execute("""
                SELECT delivered, status, payment_status, provider 
                FROM orders 
                WHERE id = %s
            """, (oid,))
            order_row = cur.fetchone()
            
            if not order_row:
                mysql.connection.rollback()
                return jsonify({"ok": False, "error": "Order not found"}), 404
            
            delivered, current_status, payment_status, provider = order_row
            
            # Normalize values
            current_status = (current_status or '').lower().strip()
            payment_status = (payment_status or '').lower().strip()
            delivered = (delivered or '').lower().strip()
            provider = (provider or '').lower().strip()
            
            # Validate if order can be cancelled
            if current_status == 'cancelled':
                mysql.connection.rollback()
                return jsonify({"ok": False, "error": "Order is already cancelled"}), 400
            
            # Smart cancellation logic based on delivery status
            delivered_truthy = delivered in ('yes', 'y', 'true', '1', 'delivered')
            
            # Validate payment status for mobile money - don't cancel if successful and money transferred  
            if payment_status == 'paid' and provider not in ('none', 'cod', ''):
                mysql.connection.rollback()
                return jsonify({"ok": False, "error": "Cannot cancel orders with successful mobile money payments. Contact payment provider for refund first."}), 400
            
            # Smart stock management - only add back stock if goods not delivered
            cancellation_message = "Order cancelled successfully"
            
            if delivered_truthy:
                # Order was delivered - customer has the product
                # Don't add stock back (customer keeps product, needs return process)
                cancellation_message = "Order cancelled. Customer has received goods - return/refund process may be needed."
            else:
                # Order not delivered - product still in warehouse 
                # Add stock back to inventory
                try:
                    update_stock_for_order(cur, oid, operation='add')
                    cancellation_message = "Order cancelled and stock returned to inventory"
                except Exception as stock_e:
                    mysql.connection.rollback()
                    return jsonify({"ok": False, "error": f"Failed to restore stock: {str(stock_e)}"}), 500
            
            # Update orders table: set status, payment_status, and delivered
            cur.execute("""
                UPDATE orders 
                SET status = 'cancelled', 
                    payment_status = 'cancelled', 
                    delivered = 'false' 
                WHERE id = %s
            """, (oid,))
            
            # Update payments table: mark any payments for this order as cancelled
            # Only update if there are actual payment records
            cur.execute("SELECT COUNT(*) FROM payments WHERE order_id = %s", (oid,))
            payment_count = cur.fetchone()[0]
            
            if payment_count > 0:
                cur.execute("""
                    UPDATE payments 
                    SET status = 'CANCELLED' 
                    WHERE order_id = %s AND status != 'SUCCESSFUL'
                """, (oid,))
            
            # COMMIT TRANSACTION
            mysql.connection.commit()
            
            # Flash message for successful cancellation
            if delivered_truthy:
                flash(f'Order #{oid} cancelled. Customer has received goods - return process may be needed.', 'warning')
            else:
                flash(f'Order #{oid} cancelled successfully and stock returned to inventory.', 'success')
            
            return jsonify({
                "ok": True, 
                "status": 'cancelled', 
                "payment_status": 'cancelled', 
                "delivered": 'false',
                "message": cancellation_message
            })
            
        except Exception as inner_e:
            mysql.connection.rollback()
            raise inner_e
            
        finally:
            cur.close()
            
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": f"Failed to cancel order: {str(e)}"}), 500

# DISABLED: Delete order - use cancellation instead for audit trail
@app.route('/api/orders/<int:oid>/delete', methods=['DELETE'])
@csrf.exempt
@login_required
def api_order_delete(oid: int):
    """
    DISABLED: Permanent deletion removed for data integrity and audit compliance
    Use cancellation instead - maintains audit trail and financial records
    """
    # Flash warning message about deletion being disabled
    flash(f'Order #{oid} deletion is disabled for audit compliance. Use Cancel Order instead.', 'warning')
    
    return jsonify({
        "ok": False, 
        "error": "Order deletion disabled for audit compliance. Use 'Cancel Order' instead.",
        "suggestion": "Cancelled orders are archived and maintain audit trail for accounting purposes.",
        "alternative": f"To remove Order {oid} from active view: Cancel the order instead of deleting it."
    }), 400


@app.route('/products')
@login_required
@check_page_permission('products')
def products():
    # Products page access (flash message removed for cleaner UX)
    
    # Get filters from query params
    q = request.args.get('q', '').strip()
    category_id = request.args.get('category', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    sort = request.args.get('sort', 'newest')
    stock_filter = request.args.get('stock', '')  # '', 'in', 'low', 'out'
    # Sales filters
    min_sales = request.args.get('min_sales', '')
    max_sales = request.args.get('max_sales', '')
    min_sales_rev = request.args.get('min_sales_rev', '')
    max_sales_rev = request.args.get('max_sales_rev', '')
    sales_days = request.args.get('sales_days', '')  # '', '7','30','90','365'
    sales_year = request.args.get('sales_year', '')  # e.g., '2025'
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = int(request.args.get('per_page', 12) or 12)
    per_page = min(max(per_page, 1), 500)  # clamp 1..500
    offset = (page - 1) * per_page
    
    try:
        cur = mysql.connection.cursor()
        
        # Get categories from database
        cur.execute("SELECT id, name FROM categories ORDER BY name")
        categories = [{'id': row[0], 'name': row[1]} for row in cur.fetchall()]
        
        # Build products query with filters
        where_conditions = []
        params = []
        
        if q:
            where_conditions.append("(p.name LIKE %s OR p.description LIKE %s)")
            params.extend([f'%{q}%', f'%{q}%'])
        
        if category_id:
            where_conditions.append("p.category_id = %s")
            params.append(category_id)
            
        if min_price:
            where_conditions.append("p.price >= %s")
            params.append(float(min_price))
            
        if max_price:
            where_conditions.append("p.price <= %s")
            params.append(float(max_price))

        # Stock filter
        sf = (stock_filter or '').lower()
        if sf == 'in':
            where_conditions.append("p.stock > %s")
            params.append(LOW_STOCK_THRESHOLD)
        elif sf == 'low':
            where_conditions.append("(p.stock > 0 AND p.stock <= %s)")
            params.append(LOW_STOCK_THRESHOLD)
        elif sf == 'out':
            where_conditions.append("p.stock = 0")
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        # Build optional sales subquery join and conditions
        sales_conditions = []
        params_sales = []
        sales_join = ""
        # Detect if orders/order_items tables exist for safety
        try:
            cur.execute("SHOW TABLES LIKE 'order_items'")
            has_oi = cur.fetchone() is not None
            cur.execute("SHOW TABLES LIKE 'orders'")
            has_o = cur.fetchone() is not None
        except Exception:
            has_oi = False
            has_o = False
        date_filter_sql = ""
        if has_oi and has_o:
            # Prefer explicit year filter over days
            if sales_year and str(sales_year).isdigit():
                date_filter_sql = "WHERE YEAR(o.created_at) = %s"
                params_sales.append(int(sales_year))
            elif sales_days and str(sales_days).isdigit():
                from datetime import date, timedelta
                df = date.today() - timedelta(days=int(sales_days))
                date_filter_sql = "WHERE o.created_at >= %s"
                params_sales.append(df)
            sales_join = (
                " LEFT JOIN ("
                " SELECT oi.product_id AS pid,"
                "        COUNT(oi.id) AS sales_count,"
                "        COALESCE(SUM(COALESCE(oi.subtotal, oi.price * oi.quantity)),0) AS sales_revenue,"
                "        COALESCE(SUM(oi.quantity),0) AS units_sold"
                "   FROM order_items oi"
                "   JOIN orders o ON o.id = oi.order_id "
                f"   {date_filter_sql}"
                "   GROUP BY oi.product_id"
                " ) s ON s.pid = p.id"
            )
            if min_sales:
                sales_conditions.append("COALESCE(s.sales_count,0) >= %s")
                params.append(int(min_sales))
            if max_sales:
                sales_conditions.append("COALESCE(s.sales_count,0) <= %s")
                params.append(int(max_sales))
            if min_sales_rev:
                sales_conditions.append("COALESCE(s.sales_revenue,0) >= %s")
                params.append(float(min_sales_rev))
            if max_sales_rev:
                sales_conditions.append("COALESCE(s.sales_revenue,0) <= %s")
                params.append(float(max_sales_rev))
            # Prepend any params from sales subquery (e.g., date_from)
            params = params_sales + params

        # Sort order with stock priority (empty first, then low stock, then normal)
        # Stock priority: 1 = empty (0), 2 = low (1-10), 3 = normal (>10)
        stock_priority = """
            CASE 
                WHEN p.stock = 0 THEN 1
                WHEN p.stock > 0 AND p.stock <= %s THEN 2
                ELSE 3
            END
        """ % LOW_STOCK_THRESHOLD
        
        if sort == 'price_low':
            order_by = f"ORDER BY {stock_priority}, p.price ASC"
        elif sort == 'price_high':
            order_by = f"ORDER BY {stock_priority}, p.price DESC"
        elif sort == 'sales_count':
            order_by = f"ORDER BY {stock_priority}, COALESCE(s.sales_count,0) DESC, p.id DESC"
        elif sort == 'sales_revenue':
            order_by = f"ORDER BY {stock_priority}, COALESCE(s.sales_revenue,0) DESC, p.id DESC"
        elif sort == 'name':
            order_by = f"ORDER BY {stock_priority}, p.name ASC"
        else:  # newest
            order_by = f"ORDER BY {stock_priority}, p.id DESC"
        # If user is filtering by sales period/year or min/max sales and did not explicitly choose a sales sort,
        # automatically prioritize most-sold products first.
        has_sales_filters = bool((sales_days and str(sales_days).isdigit()) or (sales_year and str(sales_year).isdigit()) or (min_sales) or (max_sales))
        if has_sales_filters and sales_join and sort == 'newest':
            order_by = f"ORDER BY {stock_priority}, COALESCE(s.sales_count,0) DESC, p.id DESC"
        
        # Get products with category names
        limit_clause = f"LIMIT {int(per_page)} OFFSET {int(offset)}"
        extra_sales_where = ""
        if sales_conditions:
            extra_sales_where = (" WHERE " if not where_clause else " AND ") + " AND ".join(sales_conditions)
        query = f"""
            SELECT p.id, p.name, p.price, p.stock, p.image, p.discount, c.name as category_name,
                   COALESCE(s.sales_count,0) AS sales_count,
                   COALESCE(s.sales_revenue,0) AS sales_revenue,
                   COALESCE(s.units_sold,0) AS units_sold
            FROM products p 
            LEFT JOIN categories c ON p.category_id = c.id 
            {sales_join}
            {where_clause}
            {extra_sales_where}
            {order_by}
            {limit_clause}
        """
        
        cur.execute(query, params)
        products_data = cur.fetchall()

        # Safety fallback: only when NO filters are applied at all
        no_filters = (not q) and (not category_id) and (not min_price) and (not max_price) and (not stock_filter)
        if no_filters and not products_data:
            cur.execute(
                f"""
                SELECT p.id, p.name, p.price, p.stock, p.image, p.discount, c.name as category_name
                FROM products p LEFT JOIN categories c ON p.category_id = c.id
                ORDER BY 
                    CASE 
                        WHEN p.stock = 0 THEN 1
                        WHEN p.stock > 0 AND p.stock <= {LOW_STOCK_THRESHOLD} THEN 2
                        ELSE 3
                    END,
                    p.id DESC 
                LIMIT 50
                """
            )
            products_data = cur.fetchall()
        
        products_list = []
        for row in products_data:
            # Determine stock status
            stock = row[3]
            product_id = row[0]
            if stock == 0:
                stock_status = 'out'
                stock_badge = 'OUT OF STOCK'
            elif stock <= LOW_STOCK_THRESHOLD:
                stock_status = 'low'
                stock_badge = 'LOW STOCK'
            else:
                stock_status = 'available'
                stock_badge = 'IN STOCK'
            
            # Check for variation stock mismatches and errors
            variation_errors = []
            has_variations = False
            try:
                # Check image variations sum
                cur.execute("SELECT COALESCE(SUM(stock), 0) FROM image_variations WHERE prod_id=%s", (product_id,))
                img_sum = int(cur.fetchone()[0] or 0)
                has_variations = img_sum > 0
                
                # ERROR: Image variations exceed product stock
                if img_sum > stock:
                    variation_errors.append(f"Image variations stock ({img_sum}) > product stock ({stock})")
                # WARNING: Image variations less than product stock
                elif img_sum > 0 and img_sum < stock:
                    variation_errors.append(f"Product stock ({stock}) is {stock - img_sum} units higher than total variation stock ({img_sum}). {stock - img_sum} units are unallocated.")
                
                # Check for dropdown variations that exceed their parent image variation stock
                cur.execute("""
                    SELECT iv.id, iv.stock, COALESCE(SUM(dv.stock), 0) as dropdown_sum
                    FROM image_variations iv
                    LEFT JOIN dropdown_variation dv ON dv.img_var_id = iv.id
                    WHERE iv.prod_id = %s
                    GROUP BY iv.id, iv.stock
                    HAVING COALESCE(SUM(dv.stock), 0) > 0
                """, (product_id,))
                
                for iv_row in cur.fetchall():
                    iv_id, iv_stock, dropdown_sum = iv_row
                    if dropdown_sum > iv_stock:
                        # Get the variation name for better error messaging
                        cur.execute("SELECT name FROM image_variations WHERE id=%s", (iv_id,))
                        iv_name = cur.fetchone()
                        iv_name = iv_name[0] if iv_name else f"#{iv_id}"
                        variation_errors.append(f'"{iv_name}" dropdowns ({int(dropdown_sum)}) > image var stock ({int(iv_stock)})')
                
                # Check unlinked dropdown variations sum
                cur.execute("SELECT COALESCE(SUM(stock), 0) FROM dropdown_variation WHERE prod_id=%s AND (img_var_id IS NULL OR img_var_id=0)", (product_id,))
                unlinked_sum = int(cur.fetchone()[0] or 0)
                
                if unlinked_sum > 0 and unlinked_sum < stock:
                    variation_errors.append(f"Dropdown variations stock ({unlinked_sum}) < product stock ({stock})")
            except Exception as e:
                print(f"Variation error check failed for product {product_id}: {e}")
                pass
            
            products_list.append({
                'id': row[0],
                'name': row[1],
                'price': float(row[2]),
                'stock': stock,
                'image': row[4],
                'discount': float(row[5]) if row[5] else 0,
                'category': row[6] or 'Uncategorized',
                'stock_status': stock_status,
                'stock_badge': stock_badge,
                'sales_count': int(row[7]) if len(row) > 7 else 0,
                'sales_revenue': float(row[8]) if len(row) > 8 else 0.0,
                'units_sold': float(row[9]) if len(row) > 9 else 0.0,
                'sales_year': int(sales_year) if (sales_year and str(sales_year).isdigit()) else None,
                'sales_days': int(sales_days) if (sales_days and str(sales_days).isdigit()) else None,
                'variation_errors': variation_errors,
                'has_variation_errors': len(variation_errors) > 0,
            })
        
        # Sort products by priority: errors (0) > out of stock (1) > low stock (2) > normal (3)
        def get_sort_priority(product):
            if product['has_variation_errors']:
                return 0  # Highest priority - variation errors
            elif product['stock'] == 0:
                return 1  # Out of stock
            elif product['stock'] <= LOW_STOCK_THRESHOLD:
                return 2  # Low stock
            else:
                return 3  # Normal stock
        
        # Sort with priority first, then by ID (newest first)
        products_list.sort(key=lambda p: (get_sort_priority(p), -p['id']))
        
        # Total count for pagination
        count_query = f"""
            SELECT COUNT(*)
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            {sales_join}
            {where_clause}
            {extra_sales_where}
        """
        cur.execute(count_query, params)
        total_rows = int(cur.fetchone()[0] or 0)

        # Get stats with CORRECT MATH (overall)
        cur.execute("SELECT COUNT(*) FROM products")
        total_products = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM products WHERE stock > %s", (LOW_STOCK_THRESHOLD,))
        in_stock = cur.fetchone()[0]  # Only products with stock > 5
        
        cur.execute("SELECT COUNT(*) FROM products WHERE stock > 0 AND stock <= %s", (LOW_STOCK_THRESHOLD,))
        low_stock = cur.fetchone()[0]  # Products with 1-5 stock
        
        cur.execute("SELECT COUNT(*) FROM products WHERE stock = 0")
        out_of_stock = cur.fetchone()[0]

        stats = {
            'total': total_products,
            'in_stock': in_stock,
            'low_stock': low_stock,
            'out_of_stock': out_of_stock,
        }
        
        cur.close()
        
    except Exception as e:
        print(f"Products route DB error: {e}")
        # Fallback to empty data
        categories = []
        products_list = []
        stats = {'total': 0, 'in_stock': 0, 'low_stock': 0, 'out_of_stock': 0}

    return render_template(
        "products.html",
        products=products_list,
        categories=categories,
        stats=stats,
        filters={
            'q': q,
            'category': category_id,
            'min_price': min_price,
            'max_price': max_price,
            'sort': sort,
            'stock': stock_filter,
            'min_sales': min_sales,
            'max_sales': max_sales,
            'sales_days': sales_days,
            'sales_year': sales_year,
            'per_page': per_page,
        },
        pagination={
            'page': page,
            'per_page': per_page,
            'total': total_rows,
            'pages': math.ceil(total_rows / per_page) if per_page else 1,
        }
    )

# ---------------------- Product Variations Management ----------------------
@app.route('/products/<int:pid>/variations')
@login_required
@check_page_permission('products')
def product_variations(pid):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT id, name, price, image, stock, has_variations
            FROM products WHERE id=%s
        """, (pid,))
        row = cur.fetchone()
        if not row:
            return "Product not found", 404
        
        product = {
            'id': row[0],
            'name': row[1],
            'price': float(row[2] or 0),
            'image': row[3],
            'stock': int(row[4] or 0),
            'has_variations': bool(row[5])
        }
        cur.close()
        print(f"DEBUG: Rendering variations.html for product {product['name']}")
        return render_template('variations.html', product=product)
    except Exception as e:
        print(f"ERROR in product_variations: {e}")
        import traceback
        traceback.print_exc()
        return f"Error: {e}", 500

# ---------------------- Upload API ----------------------
@app.route('/api/uploads/product-image', methods=['POST'])
@csrf.exempt
def api_upload_product_image():
    try:
        if 'image' not in request.files:
            return jsonify({"ok": False, "error": "No image file provided"}), 400
        file = request.files['image']
        if file.filename == '':
            return jsonify({"ok": False, "error": "Empty filename"}), 400
        base_name = request.form.get('name') or request.form.get('slug') or ''
        slug = slugify(base_name)
        filename = secure_filename(file.filename)
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        if ext not in ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({"ok": False, "error": "Unsupported file type"}), 400
        # Ensure upload directory exists
        upload_dir = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        # Build final filename
        ts = int(time.time())
        final_name = f"{slug}-{ts}{ext}" if slug else f"img-{ts}{ext}"
        save_path = os.path.join(upload_dir, final_name)
        file.save(save_path)
        # Public URL/path
        url_path = f"/images/{final_name}"
        return jsonify({"ok": True, "url": url_path, "filename": final_name})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/uploads/variation-image', methods=['POST'])
@csrf.exempt
def api_upload_variation_image():
    try:
        if 'image' not in request.files:
            return jsonify({"ok": False, "error": "No image file provided"}), 400
        file = request.files['image']
        if file.filename == '':
            return jsonify({"ok": False, "error": "Empty filename"}), 400
        
        base_name = request.form.get('name') or ''
        slug = slugify(base_name)
        filename = secure_filename(file.filename)
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        
        if ext not in ALLOWED_IMAGE_EXTENSIONS:
            return jsonify({"ok": False, "error": "Unsupported file type"}), 400
        
        # Upload to colors folder
        colors_dir = r"C:\Users\Public\Ecommerce website\static\images\colors"
        os.makedirs(colors_dir, exist_ok=True)
        
        # Build final filename
        ts = int(time.time())
        final_name = f"{slug}-{ts}{ext}" if slug else f"color-{ts}{ext}"
        save_path = os.path.join(colors_dir, final_name)
        file.save(save_path)
        
        # Public URL/path
        url_path = f"/images/colors/{final_name}"
        return jsonify({"ok": True, "url": url_path, "filename": final_name})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------------------- Variations API ----------------------
# Get all variations for a product
@app.route('/api/products/<int:pid>/variations', methods=['GET'])
@csrf.exempt
def api_get_product_variations(pid):
    try:
        cur = mysql.connection.cursor()
        
        # Get image variations with their linked dropdowns
        cur.execute("""
            SELECT id, type, name, description, stock, img_url
            FROM image_variations
            WHERE prod_id=%s
            ORDER BY id
        """, (pid,))
        image_vars = []
        for row in cur.fetchall():
            img_var_id = row[0]
            # Get linked dropdown variations
            cur.execute("""
                SELECT id, attr_name, attr_value, stock
                FROM dropdown_variation
                WHERE prod_id=%s AND img_var_id=%s
                ORDER BY attr_name, attr_value
            """, (pid, img_var_id))
            dropdowns = [{'id': d[0], 'attr_name': d[1], 'attr_value': d[2], 'stock': int(d[3])} for d in cur.fetchall()]
            
            image_vars.append({
                'id': img_var_id,
                'type': row[1],
                'name': row[2],
                'description': row[3],
                'stock': int(row[4]),
                'img_url': row[5],
                'dropdowns': dropdowns
            })
        
        # Get unlinked dropdown variations
        cur.execute("""
            SELECT id, attr_name, attr_value, stock
            FROM dropdown_variation
            WHERE prod_id=%s AND (img_var_id IS NULL OR img_var_id=0)
            ORDER BY attr_name, attr_value
        """, (pid,))
        unlinked = [{'id': d[0], 'attr_name': d[1], 'attr_value': d[2], 'stock': int(d[3])} for d in cur.fetchall()]
        
        cur.close()
        return jsonify({
            "ok": True,
            "image_variations": image_vars,
            "unlinked_dropdowns": unlinked
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# Add image variation
@app.route('/api/products/<int:pid>/image-variations', methods=['POST'])
@csrf.exempt
def api_add_image_variation(pid):
    try:
        data = request.get_json() or {}
        new_stock = int(data.get('stock', 0))
        
        if new_stock < 0:
            return jsonify({"ok": False, "error": "Stock cannot be negative"}), 400
        
        cur = mysql.connection.cursor()
        
        # Insert image variation - trigger will auto-increase product stock if needed
        cur.execute("""
            INSERT INTO image_variations (prod_id, type, name, description, stock, img_url)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (pid, data['type'], data['name'], data.get('description', ''), new_stock, data['img_url']))
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

# Update image variation stock
@app.route('/api/products/<int:pid>/image-variations/<int:img_var_id>', methods=['PUT'])
@csrf.exempt
def api_update_image_variation(pid, img_var_id):
    try:
        data = request.get_json() or {}
        new_stock = data.get('stock')
        new_img_url = data.get('img_url')
        
        if new_stock is None and new_img_url is None:
            return jsonify({"ok": False, "error": "Missing stock or img_url"}), 400
        
        cur = mysql.connection.cursor()
        
        # Verify image variation exists
        cur.execute("SELECT id FROM image_variations WHERE id=%s AND prod_id=%s", (img_var_id, pid))
        if not cur.fetchone():
            cur.close()
            return jsonify({"ok": False, "error": "Image variation not found"}), 404
        
        # Validate stock if provided
        if new_stock is not None:
            new_stock = int(new_stock)
            if new_stock < 0:
                cur.close()
                return jsonify({"ok": False, "error": "Stock cannot be negative"}), 400
        
        # Build update query dynamically
        update_parts = []
        update_values = []
        
        if new_stock is not None:
            update_parts.append("stock=%s")
            update_values.append(new_stock)
        
        if new_img_url is not None:
            update_parts.append("img_url=%s")
            update_values.append(new_img_url)
        
        if update_parts:
            update_values.append(img_var_id)
            query = f"UPDATE image_variations SET {', '.join(update_parts)} WHERE id=%s"
            cur.execute(query, tuple(update_values))
        
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

# Delete image variation
@app.route('/api/products/<int:pid>/image-variations/<int:img_var_id>', methods=['DELETE'])
@csrf.exempt
def api_delete_image_variation(pid, img_var_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM image_variations WHERE id=%s AND prod_id=%s", (img_var_id, pid))
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

# Add dropdown variation
@app.route('/api/products/<int:pid>/dropdown-variations', methods=['POST'])
@csrf.exempt
def api_add_dropdown_variation(pid):
    try:
        data = request.get_json() or {}
        img_var_id = data.get('img_var_id')
        new_stock = int(data.get('stock', 0))
        cur = mysql.connection.cursor()
        
        # Check for duplicate dropdown (same product, attr_name, attr_value, img_var_id)
        attr_name = data.get('attr_name', '').strip()
        attr_value = data.get('attr_value', '').strip()
        
        if img_var_id:
            # Check duplicate with image variation link
            cur.execute("""
                SELECT id FROM dropdown_variation 
                WHERE prod_id=%s AND attr_name=%s AND attr_value=%s AND img_var_id=%s
            """, (pid, attr_name, attr_value, img_var_id))
            if cur.fetchone():
                cur.close()
                return jsonify({
                    "ok": False, 
                    "error": f"Duplicate! '{attr_name}: {attr_value}' already exists for this image variation."
                }), 400
            
            # Verify image variation exists (triggers will auto-increase stock)
            cur.execute("SELECT id FROM image_variations WHERE id=%s", (img_var_id,))
            if not cur.fetchone():
                cur.close()
                return jsonify({"ok": False, "error": "Image variation not found"}), 404
        else:
            # Unlinked dropdown: check against product stock
            cur.execute("SELECT stock FROM products WHERE id=%s", (pid,))
            product_stock = int(cur.fetchone()[0] or 0)
            
            cur.execute("SELECT COALESCE(SUM(stock), 0) FROM dropdown_variation WHERE prod_id=%s AND (img_var_id IS NULL OR img_var_id=0)", (pid,))
            current_unlinked_sum = int(cur.fetchone()[0] or 0)
            
            if current_unlinked_sum + new_stock > product_stock:
                return jsonify({
                    "ok": False,
                    "error": f"Total unlinked dropdown stock ({current_unlinked_sum + new_stock}) would exceed product stock ({product_stock})"
                }), 400
        
        cur.execute("""
            INSERT INTO dropdown_variation (prod_id, attr_name, attr_value, stock, img_var_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (pid, data['attr_name'], data['attr_value'], new_stock, img_var_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

# Update dropdown variation stock
@app.route('/api/products/<int:pid>/dropdown-variations/<int:drop_id>', methods=['PUT'])
@csrf.exempt
def api_update_dropdown_variation(pid, drop_id):
    try:
        data = request.get_json() or {}
        new_stock = int(data.get('stock', 0))
        attr_name = data.get('attr_name', '').strip()
        attr_value = data.get('attr_value', '').strip()
        
        if new_stock < 0:
            return jsonify({"ok": False, "error": "Stock cannot be negative"}), 400
        
        cur = mysql.connection.cursor()
        
        # Get dropdown info
        cur.execute("SELECT img_var_id, attr_name, attr_value FROM dropdown_variation WHERE id=%s", (drop_id,))
        row = cur.fetchone()
        if not row:
            cur.close()
            return jsonify({"ok": False, "error": "Dropdown not found"}), 404
        
        img_var_id, current_attr_name, current_attr_value = row
        
        # Use current values if new ones not provided
        if not attr_name:
            attr_name = current_attr_name
        if not attr_value:
            attr_value = current_attr_value
        
        # Update all fields - trigger will auto-increase parent if needed
        cur.execute(
            "UPDATE dropdown_variation SET stock=%s, attr_name=%s, attr_value=%s WHERE id=%s", 
            (new_stock, attr_name, attr_value, drop_id)
        )
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

# Delete dropdown variation
@app.route('/api/products/<int:pid>/dropdown-variations/<int:drop_id>', methods=['DELETE'])
@csrf.exempt
def api_delete_dropdown_variation(pid, drop_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM dropdown_variation WHERE id=%s AND prod_id=%s", (drop_id, pid))
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            mysql.connection.rollback()
        except:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

# Serve variation images from the colors folder (more specific route must come first)
@app.route('/images/colors/<path:filename>')
def variation_images(filename):
    """Serve variation images with proper cache control"""
    colors_dir = r"C:\Users\Public\Ecommerce website\static\images\colors"
    response = send_from_directory(colors_dir, filename)
    
    # Same cache control as main images
    response.headers['Cache-Control'] = 'public, max-age=604800, must-revalidate'
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response

# Serve uploaded images from the configured upload folder
@app.route('/images/<path:filename>')
def uploaded_images(filename):
    """Serve images with proper cache control headers to prevent hide-and-seek"""
    response = send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    
    # Set cache control headers for images (7 days cache, but must revalidate)
    response.headers['Cache-Control'] = 'public, max-age=604800, must-revalidate'
    
    # Add ETag for cache validation
    response.headers['ETag'] = f'"{filename}-{os.path.getmtime(os.path.join(app.config["UPLOAD_FOLDER"], filename))}"'
    
    # Allow CORS for images (if needed by frontend)
    response.headers['Access-Control-Allow-Origin'] = '*'
    
    return response

# ---------------------- Reviews Page (Minimal) ----------------------
@app.route('/reviews')
@login_required
@check_page_permission('reviews')
def reviews():
    # Reviews page access (flash message removed for cleaner UX)
    
    q = (request.args.get('q') or '').strip()
    sort = request.args.get('sort', 'newest')  # newest, oldest, rating_high, rating_low
    min_rating = request.args.get('min_rating', type=float)
    max_rating = request.args.get('max_rating', type=float)
    product_filter = request.args.get('product_id', type=int)
    view_mode = (request.args.get('view') or 'cards').strip()  # 'cards' or 'list'
    unanswered_only = request.args.get('unanswered', type=int) == 1
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = int(request.args.get('per_page', 12) or 12)
    per_page = min(max(per_page, 1), 200)
    offset = (page - 1) * per_page

    items = []
    total = 0
    stats = {'total': 0, 'avg_rating': 0.0}

    try:
        cur = mysql.connection.cursor()
        # Ensure reviews table exists
        cur.execute("SHOW TABLES LIKE 'reviews'")
        if not (cur.fetchone() is not None):
            cur.close()
            return render_template('review.html', reviews=items, reviews_groups=[], product_options=[], stats=stats, filters={'q': q, 'min_rating': min_rating, 'max_rating': max_rating, 'product_id': product_filter, 'sort': sort, 'per_page': per_page, 'view': view_mode, 'unanswered': unanswered_only}, pagination={'page': page, 'per_page': per_page, 'total': 0, 'pages': 1})

        # Helper to check columns
        def has_col(tbl, col):
            cur.execute(f"SHOW COLUMNS FROM {tbl} LIKE %s", (col,))
            return cur.fetchone() is not None

        # Build SELECT
        select_bits = [
            'r.id',
            'r.product_id',
            'r.user_id',
            'COALESCE(r.rating,0) AS rating'
        ]
        body_cols = []
        if has_col('reviews','review'): body_cols.append('r.review')
        if has_col('reviews','comment'): body_cols.append('r.comment')
        if has_col('reviews','content'): body_cols.append('r.content')
        body_expr = "COALESCE(" + ", ".join(body_cols + ["''"]) + ") AS body"
        select_bits.append(body_expr)

        # Optional joins
        cur.execute("SHOW TABLES LIKE 'products'")
        has_products = cur.fetchone() is not None
        # product_name: ensure column present always with safe fallback
        product_name_in_products = False
        if has_products:
            cur.execute("SHOW COLUMNS FROM products LIKE 'name'")
            product_name_in_products = cur.fetchone() is not None
        if has_products and product_name_in_products:
            select_bits.append("COALESCE(p.name, CONCAT('PRD-', r.product_id)) AS product_name")
        else:
            select_bits.append("CONCAT('PRD-', r.product_id) AS product_name")
        cur.execute("SHOW TABLES LIKE 'users'")
        has_users_tbl = cur.fetchone() is not None
        uname_expr = None
        if has_users_tbl:
            fn_col = 'u.first_name'
            ln_col = 'u.last_name'
            un_col = 'u.username'
            # detect columns
            fn = fn_col if has_col('users','first_name') else "''"
            ln = ln_col if has_col('users','last_name') else "''"
            un = un_col if has_col('users','username') else "''"
            uname_expr = f"COALESCE(NULLIF(TRIM(CONCAT({fn}, ' ', {ln})), ''), {un}, CONCAT('User #', r.user_id)) AS user_name"
            select_bits.append(uname_expr)
        else:
            select_bits.append("CONCAT('User #', r.user_id) AS user_name")

        # Admin reply column if exists: replies/reply/replie/admin_reply
        reply_cols = []
        for cand in ['replies','reply','replie','admin_reply']:
            if has_col('reviews', cand):
                reply_cols.append(f"r.{cand}")
                break
        has_reply = len(reply_cols) > 0
        if has_reply:
            select_bits.append(reply_cols[0] + ' AS admin_reply')

        # Date column if exists
        date_col = None
        for cand in ['created_at','createdOn','created_on','date','timestamp','time','review_date','added_at']:
            if has_col('reviews', cand):
                date_col = f"r.{cand}"
                break
        if date_col:
            select_bits.append(date_col + ' AS created_at')

        # Verified buyer flag if orders + order_items exist
        cur.execute("SHOW TABLES LIKE 'orders'")
        has_orders = cur.fetchone() is not None
        cur.execute("SHOW TABLES LIKE 'order_items'")
        has_order_items = cur.fetchone() is not None
        if has_orders and has_order_items:
            select_bits.append("EXISTS(SELECT 1 FROM order_items oi JOIN orders o ON o.id = oi.order_id WHERE o.user_id = r.user_id AND oi.product_id = r.product_id) AS verified")

        from_sql = 'FROM reviews r'
        join_sql = ''
        if has_products:
            join_sql += ' LEFT JOIN products p ON p.id = r.product_id'
        if has_users_tbl:
            join_sql += ' LEFT JOIN users u ON u.id = r.user_id'

        # WHERE
        where = []
        params = []
        if q:
            like = f"%{q}%"
            parts = ["CAST(r.id AS CHAR) LIKE %s"]
            params += [like]
            # text search only on existing columns
            text_cols = []
            if has_col('reviews','review'): text_cols.append('r.review')
            if has_col('reviews','comment'): text_cols.append('r.comment')
            if has_col('reviews','content'): text_cols.append('r.content')
            if text_cols:
                parts.append("COALESCE(" + ", ".join(text_cols + ["''"]) + ") LIKE %s")
                params.append(like)
            if has_products:
                parts.append("COALESCE(p.name, '') LIKE %s")
                params.append(like)
            where.append('(' + ' OR '.join(parts) + ')')
        if product_filter is not None:
            where.append('r.product_id = %s')
            params.append(product_filter)
        if min_rating is not None:
            where.append('COALESCE(r.rating,0) >= %s')
            params.append(min_rating)
        if max_rating is not None:
            where.append('COALESCE(r.rating,0) <= %s')
            params.append(max_rating)
        if unanswered_only and has_reply:
            # Filter for reviews without admin replies
            where.append(f'({reply_cols[0]} IS NULL OR {reply_cols[0]} = "")')
        where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''

        # Sort - use date column if available for more accurate ordering
        date_sort = date_col if date_col else 'r.id'
        if sort == 'oldest':
            order_sql = f' ORDER BY {date_sort} ASC'
        elif sort == 'rating_high':
            order_sql = f' ORDER BY rating DESC, {date_sort} DESC'
        elif sort == 'rating_low':
            order_sql = f' ORDER BY rating ASC, {date_sort} ASC'
        else:
            order_sql = f' ORDER BY {date_sort} DESC'

        # Query rows
        cur.execute(
            f"SELECT {', '.join(select_bits)} {from_sql} {join_sql} {where_sql} {order_sql} LIMIT %s OFFSET %s",
            params + [per_page, offset]
        )
        rows = cur.fetchall() or []
        for rrow in rows:
            # Order: id, product_id, user_id, rating, body, product_name, user_name, [admin_reply], [created_at], [verified]
            rid = rrow[0]; pid = rrow[1]; uid = rrow[2]; rating = float(rrow[3] or 0); body = rrow[4] or ''
            idx = 5
            pname = rrow[idx]; idx += 1
            uname = rrow[idx]; idx += 1
            reply_val = None; created_at_val = None; verified_val = None
            if has_reply:
                reply_val = rrow[idx]; idx += 1
            if date_col:
                created_at_val = rrow[idx]; idx += 1
            if has_orders and has_order_items:
                verified_val = bool(rrow[idx]); idx += 1
            items.append({
                'id': rid,
                'product_id': pid,
                'user_id': uid,
                'product_name': pname or f'PRD-{pid}',
                'user_name': uname or f'User #{uid}',
                'rating': rating,
                'comment': body,
                'admin_reply': reply_val,
                'created_at': created_at_val,
                'verified': verified_val,
            })

        # Count, avg, and unanswered reviews
        cur.execute(f"SELECT COUNT(*), COALESCE(AVG(COALESCE(rating,0)),0) {from_sql} {join_sql} {where_sql}", params)
        trow = cur.fetchone()
        total = int(trow[0] or 0)
        avg_rating = float(trow[1] or 0.0)
        
        # Count unanswered reviews (no admin reply)
        unanswered_where = where_sql
        if has_reply:
            unanswered_condition = f"({reply_cols[0]} IS NULL OR {reply_cols[0]} = '')"
            if where_sql:
                unanswered_where = where_sql + f" AND {unanswered_condition}"
            else:
                unanswered_where = f" WHERE {unanswered_condition}"
            cur.execute(f"SELECT COUNT(*) {from_sql} {join_sql} {unanswered_where}", params)
            unanswered = int(cur.fetchone()[0] or 0)
        else:
            unanswered = 0
        
        stats = {'total': total, 'avg_rating': avg_rating, 'unanswered': unanswered}

        # Build product options for filter
        product_options = []
        if has_products:
            cur.execute("SHOW COLUMNS FROM products LIKE 'name'")
            if cur.fetchone():
                cur.execute("SELECT id, name FROM products ORDER BY name ASC LIMIT 500")
                for prow in cur.fetchall() or []:
                    product_options.append({'id': int(prow[0]), 'name': prow[1]})
        cur.close()
    except Exception as e:
        try:
            print('reviews route error:', e)
            cur.close()
        except Exception:
            pass

    pages = max((total + per_page - 1)//per_page, 1)
    if total and offset >= total:
        # redirect to last page if out of range
        import urllib.parse as _up
        args = request.args.to_dict(flat=True)
        args['page'] = str(pages)
        return redirect(request.path + '?' + _up.urlencode(args))

    # No user grouping - display reviews sorted by newest
    return render_template('review.html', reviews=items, product_options=product_options, stats=stats, filters={'q': q, 'min_rating': min_rating, 'max_rating': max_rating, 'product_id': product_filter, 'sort': sort, 'per_page': per_page, 'view': view_mode, 'unanswered': unanswered_only}, pagination={'page': page, 'per_page': per_page, 'total': total, 'pages': pages})

# Delete a review (composite key delete due to non-unique id in dump)
@app.route('/api/reviews/delete', methods=['POST'])
@csrf.exempt
def api_delete_review():
    try:
        data = request.get_json(force=True, silent=True) or {}
        rid = data.get('id')  # may be 0 in dump
        uid = data.get('user_id')
        pid = data.get('product_id')
        rating = data.get('rating')
        body = data.get('review') or data.get('comment') or ''
        if uid is None or pid is None:
            return jsonify({'ok': False, 'error': 'user_id and product_id required'}), 400
        cur = mysql.connection.cursor()
        # Build safe delete matching multiple fields; limit 1 avoids multiple deletions
        wh = ["user_id = %s", "product_id = %s"]
        params = [uid, pid]
        if rating is not None:
            wh.append("COALESCE(rating,0) = %s")
            params.append(int(rating))
        # Add text equality only using columns that exist
        if body:
            def has_col(tbl, col):
                cur.execute(f"SHOW COLUMNS FROM {tbl} LIKE %s", (col,))
                return cur.fetchone() is not None
            text_cols = []
            if has_col('reviews','review'): text_cols.append('review')
            if has_col('reviews','comment'): text_cols.append('comment')
            if has_col('reviews','content'): text_cols.append('content')
            if text_cols:
                if len(text_cols) == 1 and text_cols[0] == 'review':
                    wh.append("review = %s")
                    params.append(body)
                else:
                    # Dynamic COALESCE only on existing columns
                    wh.append("COALESCE(" + ", ".join(text_cols + ["''"]) + ") = %s")
                    params.append(body)
        if rid is not None:
            wh.append("id = %s")
            params.append(int(rid))
        sql = "DELETE FROM reviews WHERE " + " AND ".join(wh) + " LIMIT 1"
        cur.execute(sql, params)
        mysql.connection.commit()
        deleted = cur.rowcount
        cur.close()
        
        # Flash success message for review deletion
        if deleted > 0:
            flash('Review deleted successfully!', 'success')
        else:
            flash('Review not found or already deleted', 'warning')
        
        return jsonify({'ok': True, 'deleted': int(deleted)})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(e)}), 500
# ---------------------- Products APIs (Edit) ----------------------
@app.route('/api/products/<int:pid>')
def api_get_product(pid: int):
    try:
        cur = mysql.connection.cursor()
        # Detect optional cost_of_goods column
        cur.execute("SHOW COLUMNS FROM products LIKE 'cost_of_goods'")
        has_cogs = cur.fetchone() is not None
        if has_cogs:
            cur.execute(
                """
                SELECT id, name, price, stock, image, discount, description, category_id, cost_of_goods
                FROM products WHERE id=%s LIMIT 1
                """,
                (pid,)
            )
        else:
            cur.execute(
                """
                SELECT id, name, price, stock, image, discount, description, category_id
                FROM products WHERE id=%s LIMIT 1
                """,
                (pid,)
            )
        row = cur.fetchone()
        if not row:
            cur.close()
            return jsonify({"ok": False, "error": "Product not found"}), 404
        product = {
            "id": int(row[0]),
            "name": row[1] or "",
            "price": float(row[2]) if row[2] is not None else 0.0,
            "stock": int(row[3]) if row[3] is not None else 0,
            "image": row[4] or "",
            "discount": float(row[5]) if row[5] is not None else 0.0,
            "description": row[6] or "",
            "category_id": int(row[7]) if row[7] is not None else None,
        }
        if has_cogs:
            product["cost_of_goods"] = float(row[8]) if row[8] is not None else 0.0
        return jsonify({"ok": True, "product": product})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/products/<int:pid>/update', methods=['POST'])
@csrf.exempt
def api_update_product(pid: int):
    try:
        payload = request.get_json(force=True)
        name = (payload.get('name') or '').strip()
        price = float(payload.get('price') or 0)
        image = (payload.get('image') or '').strip()
        category_id = payload.get('category_id')
        category_id = int(category_id) if category_id not in (None, '', 'null') else None
        stock = int(payload.get('stock') or 0)
        description = (payload.get('description') or '').strip()
        discount = float(payload.get('discount') or 0)
        cost_of_goods = payload.get('cost_of_goods')
        cost_of_goods = float(cost_of_goods) if cost_of_goods not in (None, '', 'null') else None

        cur = mysql.connection.cursor()
        # Ensure product exists
        cur.execute("SELECT id FROM products WHERE id=%s", (pid,))
        if not cur.fetchone():
            cur.close()
            return jsonify({"ok": False, "error": "Product not found"}), 404

        # Build update with optional cost_of_goods
        cur.execute("SHOW COLUMNS FROM products LIKE 'cost_of_goods'")
        has_cogs = cur.fetchone() is not None
        if has_cogs:
            cur.execute(
                """
                UPDATE products
                SET name=%s, price=%s, image=%s, category_id=%s, stock=%s, description=%s, discount=%s, cost_of_goods=%s
                WHERE id=%s
                """,
                (name, price, image, category_id, stock, description, discount, cost_of_goods, pid)
            )
        else:
            cur.execute(
                """
                UPDATE products
                SET name=%s, price=%s, image=%s, category_id=%s, stock=%s, description=%s, discount=%s
                WHERE id=%s
                """,
                (name, price, image, category_id, stock, description, discount, pid)
            )
        mysql.connection.commit()
        cur.close()
        return jsonify({"ok": True})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/products/<int:pid>/sales')
def api_product_sales(pid: int):
    try:
        cur = mysql.connection.cursor()
        # Get product base info for name-based fallback and metrics
        # Detect optional columns first
        cur.execute("SHOW COLUMNS FROM products LIKE 'discount'")
        prod_has_discount_pct = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM products LIKE 'discount_amount'")
        prod_has_discount_amt = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM products LIKE 'cost_of_goods'")
        prod_has_cogs = cur.fetchone() is not None

        # Build dynamic select for products
        select_cols = ["name", "price", "stock"]
        if prod_has_discount_pct:
            select_cols.append("discount")
        else:
            select_cols.append("NULL AS discount")
        if prod_has_discount_amt:
            select_cols.append("discount_amount")
        else:
            select_cols.append("NULL AS discount_amount")
        if prod_has_cogs:
            select_cols.append("cost_of_goods")
        else:
            select_cols.append("NULL AS cost_of_goods")

        cur.execute(f"SELECT {', '.join(select_cols)} FROM products WHERE id=%s", (pid,))
        row = cur.fetchone()
        if not row:
            cur.close()
            return jsonify({"ok": False, "error": "Product not found"}), 404
        # Unpack according to dynamic select order
        prod_name = (row[0] or '').strip()
        prod_price = float(row[1] or 0)
        prod_stock = int(row[2] or 0)
        prod_discount_pct = float(row[3] or 0) if row[3] is not None else 0.0
        prod_discount_amt = float(row[4] or 0) if row[4] is not None else 0.0
        prod_cogs = float(row[5] or 0) if row[5] is not None else None

        # Detect if order_items has product_id
        cur.execute("SHOW COLUMNS FROM order_items LIKE 'product_id'")
        has_product_id = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM order_items LIKE 'product_name'")
        has_product_name = cur.fetchone() is not None

        # Detect which date column to use on orders
        date_col = 'created_at'
        for cand in ('created_at', 'date', 'order_date', 'ordered_at'):
            cur.execute("SHOW COLUMNS FROM orders LIKE %s", (cand,))
            if cur.fetchone() is not None:
                date_col = cand
                break
        # Build a robust date expression to handle VARCHAR dates in common formats
        date_expr = f"COALESCE(STR_TO_DATE(o.{date_col}, '%%Y-%%m-%%d'), STR_TO_DATE(o.{date_col}, '%%Y/%%m/%%d'), STR_TO_DATE(o.{date_col}, '%%m-%%d-%%Y'), STR_TO_DATE(o.{date_col}, '%%d-%%m-%%Y'), o.{date_col})"
        date_cmp = f"DATE({date_expr})"

        # Build WHERE clause (combine both when possible to be resilient)
        if has_product_id and has_product_name:
            where = "(oi.product_id = %s OR TRIM(oi.product_name) = TRIM(%s))"
            args = (pid, prod_name)
        elif has_product_id:
            where = "oi.product_id = %s"
            args = (pid,)
        else:
            where = "TRIM(oi.product_name) = TRIM(%s)"
            args = (prod_name,)

        # This month and last month boundaries
        cur.execute("SELECT DATE_FORMAT(CURDATE(), '%%Y-%%m-01')")
        this_month_start = cur.fetchone()[0]
        # 1st of last month
        cur.execute("SELECT DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 1 MONTH), '%%Y-%%m-01')")
        last_month_start = cur.fetchone()[0]
        # 1st of next month (for range end)
        cur.execute("SELECT DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 1 MONTH), '%%Y-%%m-01')")
        next_month_start = cur.fetchone()[0]
        # 1st of this month last year
        cur.execute("SELECT DATE_FORMAT(DATE_SUB(CURDATE(), INTERVAL 1 YEAR), '%%Y-%%m-01')")
        ly_month_start = cur.fetchone()[0]
        # 1st of the next month last year
        cur.execute("SELECT DATE_FORMAT(DATE_ADD(DATE_SUB(CURDATE(), INTERVAL 1 YEAR), INTERVAL 1 MONTH), '%%Y-%%m-01')")
        ly_next_month_start = cur.fetchone()[0]

        # Helper to aggregate for a range
        def agg_between(start_date, end_date):
            q = f"""
                SELECT COALESCE(SUM(oi.quantity),0) AS units,
                       COALESCE(SUM(oi.price * oi.quantity),0) AS revenue
                FROM order_items oi
                JOIN orders o ON o.id = oi.order_id
                WHERE {where} AND {date_cmp} >= %s AND {date_cmp} < %s
            """
            cur.execute(q, args + (start_date, end_date))
            u, r = cur.fetchone()
            return float(u or 0), float(r or 0)

        # Compute aggregates
        units_this, rev_this = agg_between(this_month_start, next_month_start)
        units_last, rev_last = agg_between(last_month_start, this_month_start)
        units_ly, rev_ly = agg_between(ly_month_start, ly_next_month_start)

        # 12-month history including this month (group by year, month)
        hist_q = f"""
            SELECT DATE_FORMAT({date_cmp}, '%%Y-%%m') AS ym,
                   COALESCE(SUM(oi.quantity),0) AS units,
                   COALESCE(SUM(oi.price * oi.quantity),0) AS revenue
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE {where} AND {date_cmp} >= DATE_SUB(DATE_FORMAT(CURDATE(), '%%Y-%%m-01'), INTERVAL 11 MONTH)
            GROUP BY ym
            ORDER BY ym ASC
        """
        cur.execute(hist_q, args)
        hist_rows = cur.fetchall()
        history = [{"month": r[0], "units": float(r[1] or 0), "revenue": float(r[2] or 0)} for r in hist_rows]

        def pct(delta, base):
            try:
                return (delta / base * 100.0) if base not in (None, 0) else None
            except Exception:
                return None

        # -------- Metrics (last 30 days window) --------
        # Period windows
        # Current: last 30 days
        # Previous: 30-60 days ago
        # Orders table may use created_at; guard with ranges similar to above
        # Orders count for product in ranges
        current_orders_q = f"""
            SELECT COUNT(oi.id), COALESCE(SUM(oi.quantity),0)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE {where} AND {date_cmp} >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        """
        cur.execute(current_orders_q, args)
        current_order_count, current_units_sold = cur.fetchone()
        current_order_count = int(current_order_count or 0)
        current_units_sold = float(current_units_sold or 0)

        prev_orders_q = f"""
            SELECT COUNT(oi.id), COALESCE(SUM(oi.quantity),0)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE {where} AND {date_cmp} < DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                  AND {date_cmp} >= DATE_SUB(CURDATE(), INTERVAL 60 DAY)
        """
        cur.execute(prev_orders_q, args)
        prev_order_count, prev_units_sold = cur.fetchone()
        prev_order_count = int(prev_order_count or 0)
        prev_units_sold = float(prev_units_sold or 0)

        # Gross Margin (per-unit): compute both list-price and discounted variants
        effective_price = prod_price
        if prod_discount_pct:
            effective_price = effective_price * (1 - (prod_discount_pct / 100.0))
        if prod_discount_amt:
            effective_price = max(effective_price - prod_discount_amt, 0.0)
        gross_margin_list = None
        gross_margin_discounted = None
        if prod_cogs is not None:
            gross_margin_list = round(prod_price - prod_cogs, 2)
            gross_margin_discounted = round(effective_price - prod_cogs, 2)

        # Conversion Rate — use product_views table if available (sum view_count last 30 days), else fallback to 1000
        cur.execute("SHOW TABLES LIKE 'product_views'")
        has_views_table = cur.fetchone() is not None
        visits_current = None
        visits_previous = None
        uses_placeholder_views = False
        if has_views_table:
            cur.execute(
                """
                SELECT COALESCE(SUM(view_count),0)
                FROM product_views
                WHERE product_id=%s AND view_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                """,
                (pid,)
            )
            visits_current = int((cur.fetchone() or (0,))[0] or 0)
            cur.execute(
                """
                SELECT COALESCE(SUM(view_count),0)
                FROM product_views
                WHERE product_id=%s AND view_date < DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                      AND view_date >= DATE_SUB(CURDATE(), INTERVAL 60 DAY)
                """,
                (pid,)
            )
            visits_previous = int((cur.fetchone() or (0,))[0] or 0)
        else:
            # Fallback placeholder for demo
            visits_current = 1000
            visits_previous = 1000
            uses_placeholder_views = True

        conv_current = (current_order_count / visits_current * 100.0) if visits_current else None
        conv_previous = (prev_order_count / visits_previous * 100.0) if visits_previous else None
        conv_change = None if (conv_current is None or conv_previous is None) else round(conv_current - conv_previous, 2)
        if conv_current is not None:
            conv_current = round(conv_current, 2)

        # Refund/Return Rate — assume orders.payment_status='failed' represents refund/cancel
        refund_current_q = f"""
            SELECT SUM(CASE WHEN LOWER(COALESCE(o.payment_status,''))='failed' THEN 1 ELSE 0 END), COUNT(oi.id)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE {where} AND {date_cmp} >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        """
        cur.execute(refund_current_q, args)
        rc_cur, tot_cur = cur.fetchone() or (0, 0)
        rc_cur = int(rc_cur or 0)
        tot_cur = int(tot_cur or 0)
        refund_rate_current = (rc_cur / tot_cur * 100.0) if tot_cur else None
        if refund_rate_current is not None:
            refund_rate_current = round(refund_rate_current, 2)

        refund_prev_q = f"""
            SELECT SUM(CASE WHEN LOWER(COALESCE(o.payment_status,''))='failed' THEN 1 ELSE 0 END), COUNT(oi.id)
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE {where} AND {date_cmp} < DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                  AND {date_cmp} >= DATE_SUB(CURDATE(), INTERVAL 60 DAY)
        """
        cur.execute(refund_prev_q, args)
        rc_prev, tot_prev = cur.fetchone() or (0, 0)
        rc_prev = int(rc_prev or 0)
        tot_prev = int(tot_prev or 0)
        refund_rate_previous = (rc_prev / tot_prev * 100.0) if tot_prev else None
        refund_rate_change = None if (refund_rate_current is None or refund_rate_previous is None) else round(refund_rate_current - refund_rate_previous, 2)

        # Days of Inventory Left (DIO)
        avg_daily_sales_current = (current_units_sold / 30.0) if current_units_sold else 0.0
        dio_current = round(prod_stock / avg_daily_sales_current, 2) if avg_daily_sales_current > 0 else None
        avg_daily_sales_previous = (prev_units_sold / 30.0) if prev_units_sold else 0.0
        dio_previous = round(prod_stock / avg_daily_sales_previous, 2) if avg_daily_sales_previous > 0 else None
        dio_change = None if (dio_current is None or dio_previous is None) else round(dio_current - dio_previous, 2)

        # Alternative MTD via grouping to cross-check
        alt_q = f"""
            SELECT COALESCE(SUM(oi.quantity),0) AS units,
                   COALESCE(SUM(oi.price*oi.quantity),0) AS revenue
            FROM order_items oi
            JOIN orders o ON o.id = oi.order_id
            WHERE {where}
              AND DATE_FORMAT({date_cmp}, '%%Y-%%m') = DATE_FORMAT(CURDATE(), '%%Y-%%m')
        """
        cur.execute(alt_q, args)
        alt_units, alt_rev = cur.fetchone()
        alt_units = float(alt_units or 0)
        alt_rev = float(alt_rev or 0)

        # Fallback: if range-based MTD is zero but equality-based has values, use alt
        if (units_this == 0 and alt_units > 0) or (rev_this == 0 and alt_rev > 0):
            units_this, rev_this = alt_units, alt_rev

        units_mom_pct = pct(units_this - units_last, units_last)
        rev_mom_pct = pct(rev_this - rev_last, rev_last)
        units_yoy_pct = pct(units_this - units_ly, units_ly)
        rev_yoy_pct = pct(rev_this - rev_ly, rev_ly)

        # Simple health heuristic
        status = 'stable'
        if (units_mom_pct is not None and units_mom_pct <= -30) or (units_yoy_pct is not None and units_yoy_pct <= -30):
            status = 'declining'
        elif (units_mom_pct is not None and units_mom_pct >= 20) or (units_yoy_pct is not None and units_yoy_pct >= 20):
            status = 'growing'

        cur.close()
        return jsonify({
            "ok": True,
            "product": {"id": pid, "name": prod_name},
            "this_month": {"units": units_this, "revenue": rev_this},
            "last_month": {"units": units_last, "revenue": rev_last},
            "last_year_same_month": {"units": units_ly, "revenue": rev_ly},
            "changes": {
                "units_mom_pct": units_mom_pct,
                "revenue_mom_pct": rev_mom_pct,
                "units_yoy_pct": units_yoy_pct,
                "revenue_yoy_pct": rev_yoy_pct
            },
            "history": history,
            "status": status,
            "metrics": {
                "gross_margin": gross_margin_list,
                "gross_margin_discounted": gross_margin_discounted,
                "gross_margin_uses_discount": False,
                "conversion_rate": conv_current,
                "conversion_rate_change": conv_change,
                "refund_rate": refund_rate_current,
                "refund_rate_change": refund_rate_change,
                "days_of_inventory_left": dio_current,
                "dio_change": dio_change
            },
            "assumptions": {
                "uses_placeholder_views": uses_placeholder_views,
                "placeholder_views_value": 1000 if uses_placeholder_views else None
            },
            "debug": {
                "date_col": date_col,
                "this_month_start": this_month_start,
                "next_month_start": next_month_start,
                "where": where,
                "args": args,
                "mtd_alt_units": alt_units,
                "mtd_alt_revenue": alt_rev
            }
        })
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/customers')
@login_required
@check_page_permission('customers')
def customers():
    # Customers page access (flash message removed for cleaner UX)
    
    q = (request.args.get('q') or '').strip()
    registered = (request.args.get('registered', '1') or '').strip()
    page = max(int(request.args.get('page', 1) or 1), 1)
    per_page = int(request.args.get('per_page', 12) or 12)
    per_page = min(max(per_page, 1), 200)
    offset = (page - 1) * per_page

    # Build dynamic WHERE for search
    where = []
    params = []
    if q:
        like = f"%{q}%"
        where.append("(o.full_name LIKE %s OR u.first_name LIKE %s OR u.last_name LIKE %s OR u.email LIKE %s OR o.delivery_phone LIKE %s OR u.phone LIKE %s)")
        params.extend([like, like, like, like, like, like])
    # Always show only registered customers on customers page
    where.append("u.id IS NOT NULL")
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    # Grouping key: prefer user_id, else phone, else name
    group_key = "COALESCE(CAST(u.id AS CHAR), NULLIF(TRIM(o.delivery_phone), ''), NULLIF(TRIM(o.full_name), ''))"

    cur = mysql.connection.cursor()
    try:
        # Detect optional per-user discount column on users: prefer 'discounts', then 'discount', then 'rate'
        cur.execute("SHOW COLUMNS FROM users LIKE 'discounts'")
        has_user_discounts = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM users LIKE 'discount'")
        has_user_discount = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM users LIKE 'rate'")
        has_user_rate = cur.fetchone() is not None
        discount_expr = "NULL"
        if has_user_discounts:
            discount_expr = "u.discounts"
        elif has_user_discount:
            discount_expr = "u.discount"
        elif has_user_rate:
            discount_expr = "u.rate"

        # Build HAVING filters on grouped metrics
        having_parts = []
        # Parse filter args
        min_orders = request.args.get('min_orders', type=int)
        max_orders = request.args.get('max_orders', type=int)
        min_spent = request.args.get('min_spent', type=float)
        max_spent = request.args.get('max_spent', type=float)
        has_discount_f = (request.args.get('has_discount') or '').lower().strip()

        if min_orders is not None:
            having_parts.append("COUNT(*) >= %s")
            params.append(min_orders)
        if max_orders is not None:
            having_parts.append("COUNT(*) <= %s")
            params.append(max_orders)
        if min_spent is not None:
            having_parts.append("COALESCE(SUM(o.total_amount),0) >= %s")
            params.append(min_spent)
        if max_spent is not None:
            having_parts.append("COALESCE(SUM(o.total_amount),0) <= %s")
            params.append(max_spent)
        if has_discount_f in ('yes','true','1'):
            having_parts.append(f"COALESCE(MAX({discount_expr}),0) > 0")
        elif has_discount_f in ('no','false','0'):
            having_parts.append(f"COALESCE(MAX({discount_expr}),0) = 0")

        having_sql = (" HAVING " + " AND ".join(having_parts)) if having_parts else ""

        # Paged customers list
        cur.execute(
            f"""
            SELECT
                MIN(o.id)                                     AS id,
                u.id                                          AS user_id,
                TRIM(COALESCE(NULLIF(o.full_name,''), CONCAT(u.first_name,' ',u.last_name))) AS name,
                NULLIF(u.email,'')                            AS email,
                COALESCE(NULLIF(TRIM(o.delivery_phone),''), NULLIF(TRIM(u.phone),'')) AS phone,
                COUNT(*)                                      AS orders_count,
                COALESCE(SUM(o.total_amount), 0)             AS total_spent,
                MAX(o.created_at)                             AS last_order_date,
                MAX({discount_expr})                          AS user_discount
            FROM orders o
            LEFT JOIN users u ON u.id = o.user_id
            {where_sql}
            GROUP BY {group_key}
            {having_sql}
            ORDER BY last_order_date DESC
            LIMIT %s OFFSET %s
            """,
            params + [per_page, offset]
        )
        rows = cur.fetchall() or []
        customers_list = []
        for r in rows:
            # Unpack with optional user_discount as the last column
            if len(r) >= 9:
                cid, user_id, name, email, phone, orders_count, total_spent, last_dt, user_discount = r
            else:
                cid, user_id, name, email, phone, orders_count, total_spent, last_dt = r
                user_discount = None
            # Simple tiering by total spent
            tier = 'CUSTOMER'
            try:
                ts = float(total_spent or 0)
                if ts >= 500000:
                    tier = 'PLATINUM'
                elif ts >= 200000:
                    tier = 'GOLD'
                elif ts >= 100000:
                    tier = 'SILVER'
            except Exception:
                pass
            customers_list.append({
                'id': cid,
                'user_id': user_id,
                'is_registered': bool(user_id),
                'name': name or '—',
                'email': email or '',
                'phone': phone or '',
                'orders_count': int(orders_count or 0),
                'total_spent': float(total_spent or 0),
                'last_order_date': last_dt.strftime('%Y-%m-%d') if hasattr(last_dt, 'strftime') else str(last_dt) if last_dt else '',
                'discount': float(user_discount) if user_discount is not None else None,
                'tier': tier,
            })

        # Total distinct customers (for pagination)
        cur.execute(
            f"""
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                {where_sql}
                GROUP BY {group_key}
            ) t
            """,
            params
        )
        total_customers = int(cur.fetchone()[0] or 0)

        # Stats - only for registered customers
        cur.execute("SELECT COALESCE(SUM(o.total_amount),0), COUNT(*) FROM orders o LEFT JOIN users u ON u.id = o.user_id WHERE u.id IS NOT NULL")
        total_spent_all, total_orders_all = cur.fetchone()

        # New registrations today (distinct registered customers who ordered today)
        cur.execute(
            f"""
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                WHERE DATE(o.created_at) = CURDATE() AND u.id IS NOT NULL
                GROUP BY {group_key}
            ) t
            """
        )
        new_today = int(cur.fetchone()[0] or 0)

        # Active users in last 30 days (registered)
        cur.execute(
            f"""
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                WHERE u.id IS NOT NULL AND o.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                GROUP BY {group_key}
            ) t
            """
        )
        active_30d = int(cur.fetchone()[0] or 0)

        # Returning users (registered customers with 2+ lifetime orders)
        cur.execute(
            f"""
            SELECT COUNT(*) FROM (
                SELECT {group_key} AS g, COUNT(*) AS cnt
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                WHERE u.id IS NOT NULL
                GROUP BY {group_key}
                HAVING cnt >= 2
            ) t
            """
        )
        returning_users = int(cur.fetchone()[0] or 0)

        # Averages across registered customers
        avg_orders_per_user = (float(total_orders_all or 0) / total_customers) if total_customers else 0.0
        avg_spend_per_user = (float(total_spent_all or 0) / total_customers) if total_customers else 0.0

        stats = {
            'total': total_customers,
            'new_today': new_today,
            'total_spent': float(total_spent_all or 0),
            'orders': int(total_orders_all or 0),
            'active_30d': active_30d,
            'returning_users': returning_users,
            'avg_orders_per_user': round(avg_orders_per_user, 2),
            'avg_spend_per_user': avg_spend_per_user,
        }
    finally:
        try:
            cur.close()
        except Exception:
            pass

    return render_template(
        "customers.html",
        customers=customers_list,
        stats=stats,
        filters={
            'q': q,
            'page': page,
            'per_page': per_page,
            'min_orders': request.args.get('min_orders',''),
            'max_orders': request.args.get('max_orders',''),
            'min_spent': request.args.get('min_spent',''),
            'max_spent': request.args.get('max_spent',''),
            'has_discount': request.args.get('has_discount',''),
        },
        pagination={
            'page': page,
            'per_page': per_page,
            'total': total_customers,
            'pages': (total_customers // per_page + (1 if total_customers % per_page else 0)),
        }
    )

@app.route('/api/customers/discount', methods=['POST'])
@csrf.exempt
def api_set_customer_discount():
    try:
        payload = request.get_json(force=True) or {}
        user_id = int(payload.get('user_id') or 0)
        discount = payload.get('discount')
        if not user_id:
            return jsonify({'ok': False, 'error': 'user_id is required'}), 400
        try:
            discount_f = float(discount)
        except Exception:
            return jsonify({'ok': False, 'error': 'discount must be a number'}), 400

        cur = mysql.connection.cursor()
        # Find the right column on users
        cur.execute("SHOW COLUMNS FROM users LIKE 'discounts'")
        has_discounts = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM users LIKE 'discount'")
        has_discount = cur.fetchone() is not None
        cur.execute("SHOW COLUMNS FROM users LIKE 'rate'")
        has_rate = cur.fetchone() is not None

        if has_discounts:
            cur.execute("UPDATE users SET discounts=%s WHERE id=%s", (discount_f, user_id))
        elif has_discount:
            cur.execute("UPDATE users SET discount=%s WHERE id=%s", (discount_f, user_id))
        elif has_rate:
            cur.execute("UPDATE users SET rate=%s WHERE id=%s", (discount_f, user_id))
        else:
            return jsonify({'ok': False, 'error': 'No discount column on users table'}), 500
        mysql.connection.commit()
        cur.close()
        return jsonify({'ok': True})
    except Exception as e:
        try:
            cur.close()
        except Exception:
            pass
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/api/customers/orders')
def api_customer_orders():
    try:
        user_id = request.args.get('user_id')
        phone = (request.args.get('phone') or '').strip()
        name = (request.args.get('name') or '').strip()
        limit = min(int(request.args.get('limit', 50) or 50), 200)

        # Use the SAME grouping logic as the customers page to ensure consistency
        # This matches the group_key from the customers query
        group_key = "COALESCE(CAST(u.id AS CHAR), NULLIF(TRIM(o.delivery_phone), ''), NULLIF(TRIM(o.full_name), ''))"
        
        # Build the WHERE condition to match the same customer group
        conditions = []
        params = []
        
        if user_id:
            # If we have user_id, find all orders for this user_id OR orders with same phone/name but no user_id
            conditions.append(f'({group_key} = %s)')
            params.append(str(user_id))
        elif phone:
            # If we have phone, find all orders grouped by this phone
            conditions.append(f'({group_key} = %s)')
            params.append(phone.strip())
        elif name:
            # If we have name, find all orders grouped by this name
            conditions.append(f'({group_key} = %s)')
            params.append(name.strip())
        else:
            return jsonify({'ok': False, 'error': 'Missing user_id/phone/name'}), 400

        where_sql = ' WHERE ' + ' OR '.join(conditions)
        
        # Detect optional payment_status column on orders
        cur = mysql.connection.cursor()
        cur.execute("SHOW COLUMNS FROM orders LIKE 'payment_status'")
        has_status_col = cur.fetchone() is not None

        select_bits = ["o.id", "o.total_amount"]
        if has_status_col:
            select_bits.append("o.payment_status")
        select_bits += [
            "o.created_at",
            "o.delivered",
            "COALESCE(o.full_name, CONCAT(u.first_name,' ',u.last_name)) AS customer_name",
            "COALESCE(o.delivery_phone, u.phone) AS phone",
        ]

        query = f"""
                SELECT {', '.join(select_bits)}
                FROM orders o
                LEFT JOIN users u ON u.id = o.user_id
                {where_sql}
                ORDER BY o.created_at DESC
                LIMIT %s
                """
        
        print(f"DEBUG: API Request - user_id: {user_id}, phone: {phone}, name: {name}")
        print(f"DEBUG: Query: {query}")
        print(f"DEBUG: Params: {params + [limit]}")
        
        try:
            cur.execute(query, params + [limit])
            orders = []
            for row in (cur.fetchall() or []):
                idx = 0
                oid = row[idx]; idx += 1
                total = row[idx]; idx += 1
                if has_status_col:
                    st = row[idx]; idx += 1
                else:
                    st = 'pending'
                created_at = row[idx]; idx += 1
                delivered = row[idx]; idx += 1
                cname = row[idx]; idx += 1
                p = row[idx] if idx < len(row) else None
                order_data = {
                    'id': oid,
                    'total_amount': float(total or 0),
                    'status': st,
                    'created_at': created_at.strftime('%Y-%m-%d %H:%M') if hasattr(created_at, 'strftime') else str(created_at),
                    'delivered': (delivered or '').strip() if isinstance(delivered, str) else (str(delivered).lower() if delivered is not None else ''),
                    'customer_name': cname,
                    'phone': p,
                }
                print(f"DEBUG: Order data: {order_data}")  # Debug log
                orders.append(order_data)
            print(f"DEBUG: Total orders found: {len(orders)}")  # Debug log
            return jsonify({'ok': True, 'orders': orders})
        finally:
            try:
                cur.close()
            except Exception:
                pass
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/inventory')
@login_required
@check_page_permission('inventory')
def inventory():
    # Simple static version for inventory management
    q = request.args.get('q', '')
    category_id = request.args.get('category', '')
    stock_filter = request.args.get('stock', '')
    sort = request.args.get('sort', 'newest')

    # Default categories
    categories = [
        {'id': 1, 'name': 'Electronics'},
        {'id': 2, 'name': 'Clothing'},
        {'id': 3, 'name': 'Books'},
        {'id': 4, 'name': 'Home & Kitchen'},
        {'id': 5, 'name': 'Sports'},
        {'id': 6, 'name': 'Beauty & Personal Care'},
        {'id': 7, 'name': 'Toys & Games'},
        {'id': 8, 'name': 'Automotive'},
        {'id': 9, 'name': 'Pet Supplies'},
        {'id': 10, 'name': 'Jewelry'},
    ]

    # Inventory stats
    stats = {
        'total_products': 165,
        'low_stock': 12,
        'out_of_stock': 8,
        'total_value': 2450000,
    }

    # Empty inventory list - will show sample data from template
    inventory_list = []

    return render_template(
        "inventory.html",
        inventory=inventory_list,
        categories=categories,
        stats=stats,
        filters={
            'q': q,
            'category': category_id,
            'stock': stock_filter,
            'sort': sort,
        },
    )
@app.route('/reports')
@login_required
@check_page_permission('reports')
def reports():
    # Flash message for reports page access
    flash('Analytics and reports generated successfully', 'info')
    
    try:
        cur = mysql.connection.cursor()
        
        # SIMPLE TEST: Just count all orders
        cur.execute("SELECT COUNT(*) FROM orders")
        test_count = cur.fetchone()[0]
        print(f"SIMPLE TEST: Total orders in DB = {test_count}")
        
        # SIMPLE TEST: Get first 5 orders grouped by date
        cur.execute("""
            SELECT DATE(created_at) as date, COUNT(*) as cnt, SUM(total_amount) as total
            FROM orders 
            GROUP BY DATE(created_at) 
            ORDER BY date DESC 
            LIMIT 5
        """)
        test_rows = cur.fetchall()
        print(f"SIMPLE TEST: First 5 date groups = {test_rows}")
        
        # Get date range filters
        start_date = request.args.get('start_date', '')
        end_date = request.args.get('end_date', '')
        
        # Pagination params (defaults)
        def to_int(v, d):
            try:
                return max(int(v), 1)
            except Exception:
                return d
        per_page = to_int(request.args.get('per_page', 20), 20)
        page_rev = to_int(request.args.get('page_rev', 1), 1)
        page_pay = to_int(request.args.get('page_pay', 1), 1)
        page_inv = to_int(request.args.get('page_inv', 1), 1)
        offset_rev = (page_rev - 1) * per_page
        offset_pay = (page_pay - 1) * per_page
        offset_inv = (page_inv - 1) * per_page
        payment_status = request.args.get('payment_status', '')
        provider = request.args.get('provider', '')
        min_value = request.args.get('min_value', '')
        max_value = request.args.get('max_value', '')
        category = request.args.get('category', '')
        
        # Get categories for dropdown
        cur.execute("SELECT id, name FROM categories ORDER BY name")
        categories = cur.fetchall()
        
        # Build filter conditions
        date_filter = ""
        status_filter = ""
        provider_filter = ""
        value_filter = ""
        category_filter = ""
        params = []
        
        # Date filter
        if start_date and end_date:
            date_filter = "AND DATE(o.created_at) BETWEEN %s AND %s"
            params.extend([start_date, end_date])
        elif start_date:
            date_filter = "AND DATE(o.created_at) >= %s"
            params.append(start_date)
        elif end_date:
            date_filter = "AND DATE(o.created_at) <= %s"
            params.append(end_date)
        
        # Payment status filter
        if payment_status:
            status_filter = "AND LOWER(o.payment_status) = %s"
            params.append(payment_status.lower())
        
        # Value range filter
        if min_value:
            value_filter += "AND o.total_amount >= %s "
            params.append(float(min_value))
        if max_value:
            value_filter += "AND o.total_amount <= %s "
            params.append(float(max_value))
        
        # Provider filter (for payments)
        provider_filter_payment = ""
        if provider:
            if provider.lower() == 'cod':
                provider_filter_payment = "AND (LOWER(p.provider) = 'cash on delivery' OR p.provider IS NULL)"
            else:
                provider_filter_payment = "AND UPPER(p.provider) = %s"
                # Note: params for this will be added separately for payments query
        
        # Category filter (for inventory)
        if category:
            category_filter = "AND p.category_id = %s"
        
        # TAB 1: REVENUE REPORT (ONLY PAID ORDERS) — paginated by date groups
        revenue_params = []
        revenue_filter = "WHERE LOWER(o.payment_status) = 'paid' "
        if date_filter:
            revenue_filter += date_filter + " "
            revenue_params.extend([p for p in params if p in [start_date, end_date]])
        if value_filter:
            revenue_filter += value_filter + " "
            revenue_params.extend([p for p in params if isinstance(p, float)])
        
        # Count total grouped rows (ONLY PAID ORDERS)
        q_rev_count = f"""
            SELECT COUNT(*) FROM (
                SELECT DATE(o.created_at) as date
                FROM orders o
                WHERE LOWER(o.payment_status) = 'paid' {date_filter}
                GROUP BY DATE(o.created_at)
            ) t
        """
        cur.execute(q_rev_count, params if params else [])
        rev_total_rows = cur.fetchone()[0] or 0
        rev_total_pages = max((rev_total_rows + per_page - 1) // per_page, 1)

        # Paged data (ONLY PAID ORDERS) with PROFIT calculation
        # Note: order_items.price is ALREADY discounted, no need to apply discounts again
        # Revenue is calculated from sum of order items, not order total_amount
        # Handle NULL product_id and missing cost_of_goods gracefully
        query_revenue = f"""
            SELECT 
                DATE(o.created_at) as date,
                COUNT(DISTINCT o.id) as orders_count,
                COALESCE(SUM(oi.quantity * oi.price), 0) as total_revenue,
                CASE 
                    WHEN COUNT(DISTINCT o.id) > 0 THEN COALESCE(SUM(oi.quantity * oi.price), 0) / COUNT(DISTINCT o.id)
                    ELSE 0
                END as average_order_value,
                COALESCE(SUM(oi.quantity * oi.price), 0) as actual_revenue,
                COALESCE(SUM(oi.quantity * IFNULL(p.cost_of_goods, 0)), 0) as total_cost,
                COALESCE(SUM(oi.quantity * oi.price), 0) - COALESCE(SUM(oi.quantity * IFNULL(p.cost_of_goods, 0)), 0) as daily_profit
            FROM orders o
            INNER JOIN order_items oi ON o.id = oi.order_id
            LEFT JOIN products p ON oi.product_id = p.id
            WHERE LOWER(o.payment_status) = 'paid' {date_filter}
            GROUP BY DATE(o.created_at)
            ORDER BY date DESC
            LIMIT %s OFFSET %s
        """
        rev_params = (params if params else []) + [per_page, offset_rev]
        print(f"DEBUG: Revenue query params = {rev_params}")
        try:
            cur.execute(query_revenue, rev_params)
            daily_revenue_summary = cur.fetchall()
            print(f"DEBUG: Revenue results count = {len(daily_revenue_summary)}")
            if daily_revenue_summary:
                print(f"DEBUG: First revenue row = {daily_revenue_summary[0]}")
        except Exception as e:
            print(f"ERROR executing revenue query: {e}")
            import traceback
            traceback.print_exc()
            daily_revenue_summary = []
        
        # Calculate totals
        # Indices: 0=date, 1=orders_count, 2=total_revenue, 3=avg_order_value, 4=actual_revenue, 5=total_cost, 6=daily_profit
        total_orders = sum(row[1] for row in daily_revenue_summary)
        grand_total_revenue = sum(row[2] for row in daily_revenue_summary)
        overall_avg_order_value = grand_total_revenue / total_orders if total_orders > 0 else 0
        total_cost = sum(row[5] for row in daily_revenue_summary)  # total_cost is index 5
        total_profit = sum(row[6] for row in daily_revenue_summary)  # daily_profit is index 6

        # DASHBOARD: Minimal KPIs (Orders-based)
        orders_where = "WHERE 1=1 "
        kpi_params = []
        
        if date_filter:
            orders_where += date_filter + " "
            kpi_params.extend([p for p in params if p in [start_date, end_date]])
        if status_filter:
            orders_where += status_filter + " "
            if payment_status:
                kpi_params.append(payment_status.lower())
        if value_filter:
            orders_where += value_filter + " "
            if min_value:
                kpi_params.append(float(min_value))
            if max_value:
                kpi_params.append(float(max_value))

        # Total revenue from paid orders
        q_total_revenue = f"""
            SELECT COALESCE(SUM(o.total_amount), 0)
            FROM orders o
            {orders_where}
            {"AND LOWER(o.payment_status) = 'paid'" if not status_filter else ""}
        """
        cur.execute(q_total_revenue, kpi_params if kpi_params else None)
        kpi_total_revenue = cur.fetchone()[0] or 0

        # Total orders
        q_total_orders = f"""
            SELECT COUNT(*)
            FROM orders o
            {orders_where}
        """
        cur.execute(q_total_orders, kpi_params if kpi_params else None)
        kpi_total_orders = cur.fetchone()[0] or 0

        # Average order value (paid orders)
        q_aov = f"""
            SELECT COALESCE(AVG(o.total_amount), 0)
            FROM orders o
            {orders_where}
            {"AND LOWER(o.payment_status) = 'paid'" if not status_filter else ""}
        """
        cur.execute(q_aov, kpi_params if kpi_params else None)
        kpi_aov = cur.fetchone()[0] or 0

        # Payments success rate only
        payments_where = "WHERE 1=1 "
        payment_rate_params = []
        if start_date or end_date:
            pay_filter = date_filter.replace('o.', 'p.') if date_filter else ""
            payments_where += pay_filter + " "
            payment_rate_params.extend([p for p in params if p in [start_date, end_date]])

        q_payment_success_rate = f"""
            SELECT 
                CASE WHEN COUNT(*) = 0 THEN 0
                     ELSE ROUND(SUM(CASE WHEN UPPER(p.status)='SUCCESSFUL' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2)
                END as success_rate
            FROM payments p
            {payments_where}
        """
        cur.execute(q_payment_success_rate, payment_rate_params if payment_rate_params else None)
        payment_success_rate = cur.fetchone()[0] or 0


        # TAB 2: PAYMENTS REPORT (SUCCESSFUL Online Payments + Paid COD Only)
        payment_params = []
        payments_filter = "WHERE UPPER(p.status) = 'SUCCESSFUL' "
        cod_filter = "WHERE LOWER(o.payment_status) = 'paid' AND NOT EXISTS (SELECT 1 FROM payments p2 WHERE p2.order_id = o.id) "
        
        if date_filter:
            payments_filter += date_filter.replace('o.', 'p.') + " "
            cod_filter += date_filter + " "
            payment_params.extend([p for p in params if p in [start_date, end_date]])
        
        # Value filter for payments
        if value_filter:
            payments_filter += value_filter.replace('o.', 'p.') + " "
            cod_filter += value_filter + " "
            if min_value:
                payment_params.append(float(min_value))
            if max_value:
                payment_params.append(float(max_value))
        
        # Provider filter
        if provider:
            if provider.lower() != 'cod':
                payments_filter += "AND UPPER(p.provider) = %s "
                payment_params.append(provider.upper())
        
        # Build the UNION query for payments
        base_union = f"""
            SELECT 
                p.order_id,
                p.amount,
                p.status,
                p.provider,
                p.payer_number,
                p.created_at,
                p.momo_transaction_id
            FROM payments p
            {payments_filter}
            
            UNION ALL
            
            SELECT 
                o.id as order_id,
                o.total_amount as amount,
                'COD' as status,
                COALESCE(o.provider, 'Cash on Delivery') as provider,
                COALESCE(o.delivery_phone, '') as payer_number,
                o.created_at,
                '' as momo_transaction_id
            FROM orders o
            {cod_filter}
        """
        
        # Count total rows in payments union
        q_pay_count = f"SELECT COUNT(*) FROM ({base_union}) t"
        cur.execute(q_pay_count, (params + params) if params else [])
        pay_total_rows = cur.fetchone()[0] or 0
        pay_total_pages = max((pay_total_rows + per_page - 1) // per_page, 1)

        # Paged payments
        query_payments = base_union + "\n ORDER BY created_at DESC LIMIT %s OFFSET %s"
        pay_params = (params + params) if params else []
        pay_params += [per_page, offset_pay]
        cur.execute(query_payments, pay_params)
        payment_details = cur.fetchall()
        
        # TAB 3: INVENTORY REPORT
        inventory_filter = ""
        inventory_params = []
        if category:
            inventory_filter = "WHERE p.category_id = %s"
            inventory_params.append(int(category))
        
        # Count products (optionally could count grouped rows; products count is sufficient)
        cur.execute("SELECT COUNT(*) FROM products")
        inv_total_rows = cur.fetchone()[0] or 0
        inv_total_pages = max((inv_total_rows + per_page - 1) // per_page, 1)

        cur.execute(f"""
            SELECT 
                p.name,
                c.name as category_name,
                p.stock,
                p.price,
                COALESCE(SUM(oi.quantity * oi.price), 0) as total_revenue
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.id
            LEFT JOIN order_items oi ON p.id = oi.product_id
            LEFT JOIN payments pay ON oi.order_id = pay.order_id AND pay.status = 'SUCCESSFUL'
            {inventory_filter}
            GROUP BY p.id, p.name, c.name, p.stock, p.price
            ORDER BY total_revenue DESC
            LIMIT %s OFFSET %s
        """, [per_page, offset_inv])
        inventory_details = cur.fetchall()
        
        cur.close()
        
        return render_template("reports.html",
            daily_revenue_summary=daily_revenue_summary,
            payment_details=payment_details,
            inventory_details=inventory_details,
            total_orders=total_orders,
            grand_total_revenue=grand_total_revenue,
            overall_avg_order_value=overall_avg_order_value,
            total_profit=total_profit,
            total_cost=total_cost,
            # Minimal dashboard KPIs
            kpi_total_revenue=kpi_total_revenue,
            kpi_total_orders=kpi_total_orders,
            kpi_aov=kpi_aov,
            payment_success_rate=payment_success_rate,
            start_date=start_date,
            end_date=end_date,
            categories=categories,
            # Paginators
            revenue_pager={
                'page': page_rev,
                'pages': rev_total_pages,
                'per_page': per_page,
                'total': rev_total_rows,
            },
            payments_pager={
                'page': page_pay,
                'pages': pay_total_pages,
                'per_page': per_page,
                'total': pay_total_rows,
            },
            inventory_pager={
                'page': page_inv,
                'pages': inv_total_pages,
                'per_page': per_page,
                'total': inv_total_rows,
            }
        )
    except Exception as e:
        print(f"Reports error: {e}")
        # Provide safe defaults for template variables
        return render_template(
            "reports.html",
            error=str(e),
            daily_revenue_summary=[],
            payment_details=[],
            inventory_details=[],
            total_orders=0,
            grand_total_revenue=0,
            overall_avg_order_value=0,
            kpi_total_revenue=0,
            kpi_total_orders=0,
            kpi_aov=0,
            orders_by_status=[],
            revenue_timeseries=[],
            top_products=[],
            sales_by_category=[],
            payment_status_counts=[],
            payments_by_provider=[],
            payment_success_rate=0,
            low_stock=[],
            review_rating_dist=[],
            top_rated_products=[],
            order_locations=[],
            wishlist_top=[],
            start_date=request.args.get('start_date',''),
            end_date=request.args.get('end_date',''),
        )

@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html")

@app.route('/profile/update', methods=['POST'])
@login_required
def profile_update():
    """Update username in worker_login table"""
    try:
        new_username = request.form.get('username', '').strip()
        
        if not new_username:
            flash('Username cannot be empty', 'error')
            return redirect('/profile')
        
        # Check if username is already taken by another user
        cur = mysql.connection.cursor()
        cur.execute("SELECT login_id FROM worker_login WHERE username = %s AND worker_id != %s", 
                   (new_username, session['worker_id']))
        if cur.fetchone():
            cur.close()
            flash('Username already taken. Please choose another.', 'error')
            return redirect('/profile')
        
        # Update username
        cur.execute("""
            UPDATE worker_login 
            SET username = %s 
            WHERE worker_id = %s
        """, (new_username, session['worker_id']))
        
        mysql.connection.commit()
        cur.close()
        
        # Update session
        session['username'] = new_username
        
        flash('Username updated successfully!', 'success')
        return redirect('/profile')
        
    except Exception as e:
        print(f"Profile update error: {e}")
        flash(f'Error updating profile: {str(e)}', 'error')
        return redirect('/profile')

@app.route('/profile/change-password', methods=['POST'])
@login_required
def profile_change_password():
    """Change password in worker_login table"""
    try:
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not all([current_password, new_password, confirm_password]):
            flash('All password fields are required', 'error')
            return redirect('/profile')
        
        # Check if new passwords match
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect('/profile')
        
        # Validate new password strength
        if not PASSWORD_REGEX.match(new_password):
            flash('Password must be at least 8 characters and include uppercase, lowercase, number, and special character', 'error')
            return redirect('/profile')
        
        # Get current password hash
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT password FROM worker_login 
            WHERE worker_id = %s
        """, (session['worker_id'],))
        
        result = cur.fetchone()
        if not result:
            cur.close()
            flash('User login not found', 'error')
            return redirect('/profile')
        
        current_hash = result[0]
        
        # Verify current password
        if not check_password_hash(current_hash, current_password):
            cur.close()
            flash('Current password is incorrect', 'error')
            return redirect('/profile')
        
        # Hash new password
        new_hash = generate_password_hash(new_password)
        
        # Update password
        cur.execute("""
            UPDATE worker_login 
            SET password = %s 
            WHERE worker_id = %s
        """, (new_hash, session['worker_id']))
        
        mysql.connection.commit()
        cur.close()
        
        flash('Password changed successfully!', 'success')
        return redirect('/profile')
        
    except Exception as e:
        print(f"Password change error: {e}")
        flash(f'Error changing password: {str(e)}', 'error')
        return redirect('/profile')

# ============= WORKERS MANAGEMENT =============
@app.route('/workers')
@login_required
@check_page_permission('workers')
def workers():
    """Display all users"""
    # Workers page access (flash message removed for cleaner UX)
    
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT w.worker_id, w.name, w.phone, w.email, w.salary, w.profession, w.deptName, w.created_at,
                   CASE WHEN wl.worker_id IS NOT NULL THEN 1 ELSE 0 END as is_registered
            FROM workers w
            LEFT JOIN worker_login wl ON w.worker_id = wl.worker_id
            ORDER BY w.created_at DESC
        """)
        workers_list = cur.fetchall()
        cur.close()
        return render_template("workers.html", workers=workers_list)
    except Exception as e:
        print(f"Workers page error: {e}")
        return render_template("workers.html", workers=[], error=str(e))

@app.route('/workers/add', methods=['POST'])
@login_required
@check_page_permission('workers')
def add_worker():
    """Add a new user (admin only)"""
    try:
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        salary = request.form.get('salary')
        profession = request.form.get('profession')
        department = request.form.get('department', 'General')  # Default to 'General'
        
        # Validate email
        is_valid_email, email_error = validate_email(email)
        if not is_valid_email:
            flash(f'Email validation failed: {email_error}', 'error')
            return redirect('/workers')
        
        cur = mysql.connection.cursor()
        
        # Check if email already exists
        cur.execute("SELECT worker_id, name FROM workers WHERE email = %s", (email.strip().lower(),))
        existing = cur.fetchone()
        if existing:
            cur.close()
            flash(f'Email already exists for worker: {existing[1]}', 'error')
            return redirect('/workers')
        
        cur.execute("""
            INSERT INTO workers (name, phone, email, salary, profession, deptName, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
        """, (name, phone, email.strip().lower(), salary, profession, department))
        
        # Get the newly created worker_id
        worker_id = cur.lastrowid
        
        # Give them full access to all pages by default
        all_pages = ['dashboard', 'orders', 'products', 'reviews', 'customers', 'workers', 'reports']
        for page in all_pages:
            cur.execute("""
                INSERT INTO worker_page_permissions (worker_id, pages)
                VALUES (%s, %s)
            """, (worker_id, page))
        
        mysql.connection.commit()
        cur.close()
        
        # Send welcome email
        try:
            msg = Message(
                subject='Welcome to Dashboard - Your Account Has Been Created',
                recipients=[email.strip().lower()],
                sender=('Dashboard Team', app.config['MAIL_USERNAME'])
            )
            
            # Get registration URL
            register_url = request.url_root + 'register'
            
            msg.html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
                    <tr>
                        <td align="center" style="padding: 40px 20px;">
                            <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                                <!-- Header -->
                                <tr>
                                    <td style="background-color: #228B22; padding: 30px; text-align: center;">
                                        <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 600;">Welcome to the Team!</h1>
                                        <p style="margin: 10px 0 0 0; color: #ffffff; font-size: 16px;">You've been added to Dashboard</p>
                                    </td>
                                </tr>
                                
                                <!-- Content -->
                                <tr>
                                    <td style="padding: 40px;">
                                        <p style="margin: 0 0 16px 0; color: #555555; font-size: 15px; line-height: 1.6;">Hello <strong>{name}</strong>,</p>
                                        <p style="margin: 0 0 16px 0; color: #555555; font-size: 15px; line-height: 1.6;">Great news! You have been added to our Dashboard team. We're excited to have you on board!</p>
                                        
                                        <!-- Account Details Box -->
                                        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f0f8f0; border-left: 4px solid #228B22; margin: 24px 0;">
                                            <tr>
                                                <td style="padding: 20px;">
                                                    <h2 style="margin: 0 0 16px 0; color: #228B22; font-size: 20px;">Your Account Details</h2>
                                                    <table width="100%" cellpadding="8" cellspacing="0" border="0">
                                                        <tr>
                                                            <td style="background-color: #f8f9fa; border-radius: 4px; padding: 12px; font-size: 14px;">
                                                                <strong style="color: #666666;">Name:</strong> {name}
                                                            </td>
                                                        </tr>
                                                        <tr><td style="height: 8px;"></td></tr>
                                                        <tr>
                                                            <td style="background-color: #f8f9fa; border-radius: 4px; padding: 12px; font-size: 14px;">
                                                                <strong style="color: #666666;">Email:</strong> {email.strip().lower()}
                                                            </td>
                                                        </tr>
                                                        <tr><td style="height: 8px;"></td></tr>
                                                        <tr>
                                                            <td style="background-color: #f8f9fa; border-radius: 4px; padding: 12px; font-size: 14px;">
                                                                <strong style="color: #666666;">Position:</strong> {profession}
                                                            </td>
                                                        </tr>
                                                        <tr><td style="height: 8px;"></td></tr>
                                                        <tr>
                                                            <td style="background-color: #f8f9fa; border-radius: 4px; padding: 12px; font-size: 14px;">
                                                                <strong style="color: #666666;">Department:</strong> {department}
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <!-- Steps Box -->
                                        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f8f9fa; margin: 24px 0;">
                                            <tr>
                                                <td style="padding: 20px;">
                                                    <h3 style="margin: 0 0 16px 0; color: #333333; font-size: 18px;">Next Steps - Complete Your Registration</h3>
                                                    <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                                        <tr>
                                                            <td width="30" valign="top">
                                                                <div style="background-color: #228B22; color: white; width: 24px; height: 24px; border-radius: 50%; text-align: center; line-height: 24px; font-size: 14px; font-weight: bold;">1</div>
                                                            </td>
                                                            <td style="padding-left: 10px; padding-bottom: 12px;">
                                                                <strong style="color: #333333; font-size: 15px;">Click the registration button below</strong>
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td width="30" valign="top">
                                                                <div style="background-color: #228B22; color: white; width: 24px; height: 24px; border-radius: 50%; text-align: center; line-height: 24px; font-size: 14px; font-weight: bold;">2</div>
                                                            </td>
                                                            <td style="padding-left: 10px; padding-bottom: 12px;">
                                                                <strong style="color: #333333; font-size: 15px;">Use your email: {email.strip().lower()}</strong>
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td width="30" valign="top">
                                                                <div style="background-color: #228B22; color: white; width: 24px; height: 24px; border-radius: 50%; text-align: center; line-height: 24px; font-size: 14px; font-weight: bold;">3</div>
                                                            </td>
                                                            <td style="padding-left: 10px; padding-bottom: 12px;">
                                                                <strong style="color: #333333; font-size: 15px;">Create a username and secure password</strong>
                                                            </td>
                                                        </tr>
                                                        <tr>
                                                            <td width="30" valign="top">
                                                                <div style="background-color: #228B22; color: white; width: 24px; height: 24px; border-radius: 50%; text-align: center; line-height: 24px; font-size: 14px; font-weight: bold;">4</div>
                                                            </td>
                                                            <td style="padding-left: 10px;">
                                                                <strong style="color: #333333; font-size: 15px;">Login and start working!</strong>
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <!-- Button -->
                                        <table width="100%" cellpadding="0" cellspacing="0" border="0">
                                            <tr>
                                                <td align="center" style="padding: 20px 0;">
                                                    <a href="{register_url}" style="display: inline-block; background-color: #228B22; color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">Complete Registration</a>
                                                </td>
                                            </tr>
                                        </table>
                                        
                                        <p style="margin: 32px 0 0 0; color: #666666; font-size: 14px; line-height: 1.6;">
                                            If you have any questions or need assistance, please contact your administrator.
                                        </p>
                                        
                                        <p style="margin: 24px 0 0 0; color: #555555; font-size: 15px; line-height: 1.6;">
                                            Welcome aboard!<br><strong style="color: #228B22;">Dashboard Team</strong>
                                        </p>
                                    </td>
                                </tr>
                                
                                <!-- Footer -->
                                <tr>
                                    <td style="background-color: #f8f9fa; padding: 24px; text-align: center; border-top: 1px solid #e0e0e0;">
                                        <p style="margin: 0 0 8px 0; color: #888888; font-size: 13px;">This is an automated notification from Dashboard.</p>
                                        <p style="margin: 0; color: #888888; font-size: 13px;">&copy; 2025 Dashboard. All rights reserved.</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            """
            
            mail.send(msg)
            print(f"Welcome email sent to {email}")
            
        except Exception as email_error:
            # Don't fail the worker creation if email fails
            print(f"Failed to send welcome email: {email_error}")
        
        flash('User added successfully! Welcome email sent.', 'success')
        return redirect('/workers')
    except Exception as e:
        print(f"Add worker error: {e}")
        flash(f'Error adding user: {str(e)}', 'error')
        return redirect('/workers')

@app.route('/workers/get/<int:worker_id>')
@login_required
@check_page_permission('workers')
def get_worker(worker_id):
    """Get user details by ID (API endpoint)"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT worker_id, name, phone, email, salary, profession, deptName 
            FROM workers 
            WHERE worker_id = %s
        """, (worker_id,))
        worker = cur.fetchone()
        cur.close()
        
        if worker:
            return jsonify({
                'ok': True,
                'worker': {
                    'id': worker[0],
                    'name': worker[1],
                    'phone': worker[2],
                    'email': worker[3],
                    'salary': float(worker[4]),
                    'profession': worker[5],
                    'department': worker[6]
                }
            })
        else:
            return jsonify({'ok': False, 'error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/workers/edit', methods=['POST'])
@login_required
@check_page_permission('workers')
def edit_worker():
    """Edit an existing user (admin only)"""
    try:
        worker_id = request.form.get('worker_id')
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        salary = request.form.get('salary')
        profession = request.form.get('profession')
        department = request.form.get('department', 'General')  # Default to 'General'
        
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE workers 
            SET name = %s, phone = %s, email = %s, salary = %s, profession = %s, deptName = %s
            WHERE worker_id = %s
        """, (name, phone, email, salary, profession, department, worker_id))
        mysql.connection.commit()
        cur.close()
        
        flash('User updated successfully!', 'success')
        return redirect('/workers')
    except Exception as e:
        print(f"Edit worker error: {e}")
        flash(f'Error updating user: {str(e)}', 'error')
        return redirect('/workers')

@app.route('/workers/delete/<int:worker_id>', methods=['POST'])
@csrf.exempt
def delete_worker(worker_id):
    """Delete a user"""
    try:
        cur = mysql.connection.cursor()
        
        # Get worker details before deleting
        cur.execute("SELECT name, email FROM workers WHERE worker_id = %s", (worker_id,))
        worker = cur.fetchone()
        if not worker:
            return jsonify({'ok': False, 'error': 'Worker not found'}), 404
            
        worker_name = worker[0]
        worker_email = worker[1]
        
        # Delete worker
        cur.execute("DELETE FROM workers WHERE worker_id = %s", (worker_id,))
        mysql.connection.commit()
        cur.close()
        
        # Send goodbye email
        try:
            if worker_email:
                msg = Message(
                    subject='Account Removed - Dashboard',
                    recipients=[worker_email],
                    sender=('Dashboard Team', app.config['MAIL_USERNAME'])
                )
                
                msg.html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body {{ 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
                            line-height: 1.6; 
                            color: #333333;
                            background-color: #f5f5f5;
                            margin: 0;
                            padding: 0;
                        }}
                        .email-wrapper {{ 
                            max-width: 600px; 
                            margin: 40px auto; 
                            background-color: #ffffff;
                            border: 1px solid #e0e0e0;
                            border-radius: 8px;
                            overflow: hidden;
                        }}
                        .header {{ 
                            background-color: #dc3545;
                            color: #ffffff; 
                            padding: 30px 40px; 
                            text-align: center;
                        }}
                        .header h1 {{ 
                            margin: 0;
                            font-size: 24px;
                            font-weight: 600;
                        }}
                        .content {{ 
                            padding: 40px; 
                            background-color: #ffffff;
                        }}
                        .content p {{
                            margin: 0 0 16px 0;
                            color: #555555;
                            font-size: 15px;
                        }}
                        .info-box {{ 
                            background-color: #fff3cd; 
                            border-left: 4px solid #ffc107; 
                            padding: 16px 20px; 
                            margin: 24px 0;
                            border-radius: 4px;
                        }}
                        .info-box p {{
                            margin: 0;
                            color: #856404;
                            font-size: 14px;
                        }}
                        .footer {{ 
                            background-color: #f8f9fa;
                            padding: 24px 40px;
                            text-align: center;
                            border-top: 1px solid #e0e0e0;
                        }}
                        .footer p {{ 
                            color: #888888; 
                            font-size: 13px;
                            margin: 0 0 8px 0;
                        }}
                    </style>
                </head>
                <body>
                    <div class="email-wrapper">
                        <div class="header">
                            <h1>Account Removed</h1>
                        </div>
                        <div class="content">
                            <p>Hello <strong>{worker_name}</strong>,</p>
                            <p>Your account has been removed from the Dashboard system by an administrator.</p>
                            
                            <div class="info-box">
                                <p><strong>Important:</strong> Your account and all associated data have been permanently deleted from our system.</p>
                            </div>
                            
                            <p>If you believe this was done in error, please contact your administrator immediately.</p>
                            
                            <p style="margin-top: 32px;">Thank you for your time with us.</p>
                        </div>
                        <div class="footer">
                            <p>This is an automated notification from Dashboard.</p>
                            <p>&copy; 2025 Dashboard. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                mail.send(msg)
                print(f"Deletion notification sent to {worker_email}")
        except Exception as email_error:
            print(f"Failed to send deletion email: {email_error}")
        
        # Flash success message for worker deletion
        flash(f'User "{worker_name}" deleted successfully!', 'success')
        
        return jsonify({'ok': True, 'message': 'User deleted successfully'})
    except Exception as e:
        print(f"Delete worker error: {e}")
        flash(f'Error deleting user: {str(e)}', 'error')
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/workers/permissions/<int:worker_id>')
@login_required
@check_page_permission('workers')
def get_worker_permissions(worker_id):
    """Get pages that a worker has access to (admin only)"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT pages FROM worker_page_permissions WHERE worker_id = %s", (worker_id,))
        rows = cur.fetchall()
        cur.close()
        
        # Extract all pages from rows
        permissions = [row[0] for row in rows]
        
        return jsonify({'ok': True, 'permissions': permissions})
    except Exception as e:
        print(f"Get permissions error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/workers/permissions/update', methods=['POST'])
@csrf.exempt
@login_required
@check_page_permission('workers')
def update_worker_permissions():
    """Update worker page permissions (admin only)"""
    try:
        data = request.get_json()
        worker_id = data.get('worker_id')
        pages = data.get('pages', [])
        
        cur = mysql.connection.cursor()
        
        # Delete existing permissions for this worker
        cur.execute("DELETE FROM worker_page_permissions WHERE worker_id = %s", (worker_id,))
        
        # Insert new permissions
        for page in pages:
            cur.execute("""
                INSERT INTO worker_page_permissions (worker_id, pages)
                VALUES (%s, %s)
            """, (worker_id, page))
        
        mysql.connection.commit()
        cur.close()
        
        return jsonify({'ok': True, 'message': 'Permissions updated successfully'})
    except Exception as e:
        print(f"Update permissions error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/workers/send-email', methods=['POST'])
@csrf.exempt
@login_required
@check_page_permission('workers')
def send_email_to_worker():
    """Send custom email to a worker"""
    try:
        data = request.get_json()
        worker_email = data.get('worker_email')
        subject = data.get('subject')
        message = data.get('message')
        
        if not all([worker_email, subject, message]):
            return jsonify({'ok': False, 'error': 'Missing required fields'}), 400
        
        # Get sender name from session
        sender_name = session.get('name', 'Dashboard Admin')
        
        # Send email
        msg = Message(
            subject=subject,
            recipients=[worker_email],
            sender=('Dashboard Team', app.config['MAIL_USERNAME'])
        )
        
        # Create email HTML with table-based layout for Gmail compatibility
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
                <tr>
                    <td align="center" style="padding: 40px 20px;">
                        <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; overflow: hidden;">
                            <!-- Header -->
                            <tr>
                                <td style="background-color: #228B22; padding: 30px; text-align: center;">
                                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 600;">{subject}</h1>
                                </td>
                            </tr>
                            
                            <!-- Content -->
                            <tr>
                                <td style="padding: 40px;">
                                    <div style="color: #555555; font-size: 15px; line-height: 1.8; white-space: pre-wrap;">{message}</div>
                                    
                                    <p style="margin: 32px 0 0 0; color: #555555; font-size: 15px; line-height: 1.6;">
                                        Best regards,<br><strong style="color: #228B22;">{sender_name}</strong>
                                    </p>
                                </td>
                            </tr>
                            
                            <!-- Footer -->
                            <tr>
                                <td style="background-color: #f8f9fa; padding: 24px; text-align: center; border-top: 1px solid #e0e0e0;">
                                    <p style="margin: 0 0 8px 0; color: #888888; font-size: 13px;">This email was sent from Dashboard.</p>
                                    <p style="margin: 0; color: #888888; font-size: 13px;">&copy; 2025 Dashboard. All rights reserved.</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """
        
        mail.send(msg)
        print(f"Custom email sent to {worker_email}")
        
        return jsonify({'ok': True, 'message': 'Email sent successfully'})
    except Exception as e:
        print(f"Send email error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/workers/get-reset-code/<int:worker_id>', methods=['POST'])
@csrf.exempt
@login_required
@check_page_permission('workers')
def get_reset_code(worker_id):
    """Generate password reset code for a worker"""
    try:
        cur = mysql.connection.cursor()
        
        # Get worker info
        cur.execute("""
            SELECT wl.username, w.name, w.email
            FROM worker_login wl
            JOIN workers w ON wl.worker_id = w.worker_id
            WHERE w.worker_id = %s
        """, (worker_id,))
        
        worker = cur.fetchone()
        cur.close()
        
        if not worker:
            return jsonify({'ok': False, 'error': 'Worker or login not found'}), 404
        
        username, name, email = worker
        
        # Generate reset code (first 4 chars of username + worker_id)
        reset_code = f"{username[:4].upper()}{worker_id:04d}"
        
        return jsonify({
            'ok': True, 
            'reset_code': reset_code,
            'username': username,
            'name': name,
            'email': email
        })
    except Exception as e:
        print(f"Get reset code error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/workers/reset-login/<int:worker_id>', methods=['POST'])
@csrf.exempt
@login_required
@check_page_permission('workers')
def reset_worker_login(worker_id):
    """Delete worker login credentials so they can register again"""
    try:
        cur = mysql.connection.cursor()
        
        # Check if worker exists and get their details
        cur.execute("SELECT worker_id, name, email FROM workers WHERE worker_id = %s", (worker_id,))
        worker = cur.fetchone()
        
        if not worker:
            cur.close()
            return jsonify({'ok': False, 'error': 'Worker not found'}), 404
        
        worker_name = worker[1]
        worker_email = worker[2]
        
        # Check if worker has login credentials
        cur.execute("SELECT login_id FROM worker_login WHERE worker_id = %s", (worker_id,))
        login_exists = cur.fetchone()
        
        if not login_exists:
            cur.close()
            return jsonify({'ok': False, 'error': 'Worker has no login credentials to reset'}), 400
        
        # Delete login credentials
        cur.execute("DELETE FROM worker_login WHERE worker_id = %s", (worker_id,))
        mysql.connection.commit()
        cur.close()
        
        # Send reset notification email
        try:
            if worker_email:
                msg = Message(
                    subject='Login Credentials Reset - Dashboard',
                    recipients=[worker_email],
                    sender=('Dashboard Team', app.config['MAIL_USERNAME'])
                )
                
                register_url = request.url_root + 'register'
                
                msg.html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <style>
                        body {{ 
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
                            line-height: 1.6; 
                            color: #333333;
                            background-color: #f5f5f5;
                            margin: 0;
                            padding: 0;
                        }}
                        .email-wrapper {{ 
                            max-width: 600px; 
                            margin: 40px auto; 
                            background-color: #ffffff;
                            border: 1px solid #e0e0e0;
                            border-radius: 8px;
                            overflow: hidden;
                        }}
                        .header {{ 
                            background-color: #ff9800;
                            color: #ffffff; 
                            padding: 30px 40px; 
                            text-align: center;
                        }}
                        .header h1 {{ 
                            margin: 0;
                            font-size: 24px;
                            font-weight: 600;
                        }}
                        .header p {{
                            margin: 8px 0 0 0;
                            font-size: 14px;
                            opacity: 0.9;
                        }}
                        .content {{ 
                            padding: 40px; 
                            background-color: #ffffff;
                        }}
                        .content p {{
                            margin: 0 0 16px 0;
                            color: #555555;
                            font-size: 15px;
                        }}
                        .info-box {{ 
                            background-color: #fff8e1; 
                            border-left: 4px solid #ff9800; 
                            padding: 16px 20px; 
                            margin: 24px 0;
                            border-radius: 4px;
                        }}
                        .info-box p {{
                            margin: 0;
                            color: #e65100;
                            font-size: 14px;
                        }}
                        .cta-button {{
                            display: inline-block;
                            background-color: #ff9800;
                            color: #ffffff;
                            padding: 14px 32px;
                            text-decoration: none;
                            border-radius: 6px;
                            font-weight: 600;
                            margin: 20px 0;
                            text-align: center;
                        }}
                        .footer {{ 
                            background-color: #f8f9fa;
                            padding: 24px 40px;
                            text-align: center;
                            border-top: 1px solid #e0e0e0;
                        }}
                        .footer p {{ 
                            color: #888888; 
                            font-size: 13px;
                            margin: 0 0 8px 0;
                        }}
                    </style>
                </head>
                <body>
                    <div class="email-wrapper">
                        <div class="header">
                            <h1>Login Credentials Reset</h1>
                            <p>Action Required</p>
                        </div>
                        <div class="content">
                            <p>Hello <strong>{worker_name}</strong>,</p>
                            <p>Your login credentials for Dashboard have been reset by an administrator.</p>
                            
                            <div class="info-box">
                                <p><strong>What This Means:</strong> Your username and password have been removed from the system. You need to register again to regain access.</p>
                            </div>
                            
                            <p><strong>To regain access:</strong></p>
                            <ol style="color: #555555; font-size: 15px; line-height: 1.8;">
                                <li>Click the registration button below</li>
                                <li>Use your email: <strong>{worker_email}</strong></li>
                                <li>Create a new username and password</li>
                                <li>Login with your new credentials</li>
                            </ol>
                            
                            <center>
                                <a href="{register_url}" class="cta-button">Register Now</a>
                            </center>
                            
                            <p style="margin-top: 32px; font-size: 14px; color: #666666;">
                                If you have any questions or did not request this reset, please contact your administrator.
                            </p>
                        </div>
                        <div class="footer">
                            <p>This is an automated notification from Dashboard.</p>
                            <p>&copy; 2025 Dashboard. All rights reserved.</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                mail.send(msg)
                print(f"Reset notification sent to {worker_email}")
        except Exception as email_error:
            print(f"Failed to send reset email: {email_error}")
        
        return jsonify({'ok': True, 'message': f'Login credentials reset for {worker_name}. They can now register again.'})
    except Exception as e:
        print(f"Reset login error: {e}")
        return jsonify({'ok': False, 'error': str(e)}), 500

# ============= ACCESS DENIED PAGE =============
@app.route('/access-denied')
@login_required
def access_denied():
    """Show access denied page with available pages"""
    if 'worker_id' not in session:
        return redirect('/login')
    
    try:
        cur = mysql.connection.cursor()
        # Get all pages this worker has permission to access
        cur.execute("""
            SELECT pages FROM worker_page_permissions 
            WHERE worker_id = %s
            ORDER BY pages
        """, (session['worker_id'],))
        permissions = cur.fetchall()
        cur.close()
        
        available_pages = [p[0] for p in permissions]
        
        # If user has at least one permission, redirect to first available page
        if available_pages:
            first_page = available_pages[0]
            return redirect(f'/{first_page}')
        
        # No permissions - show error page
        return render_template('access_denied.html', available_pages=[])
    except Exception as e:
        print(f"Access denied page error: {e}")
        return render_template('access_denied.html', available_pages=[])

# ============= LOGIN SYSTEM =============
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit login attempts
def login():
    """Worker login - checks worker_login table"""
    if 'logged_in' in session:
        return redirect('/')
    
    # Get the next URL if user was redirected from a protected page
    next_url = request.args.get('next')
    
    if request.method == 'POST':
        username_or_email = request.form.get('username')
        password = request.form.get('password')
        
        if not username_or_email or not password:
            flash('Please enter both username/email and password', 'error')
            return redirect('/login')
        
        # Check if user is locked out
        allowed, message = check_login_attempts(username_or_email)
        if not allowed:
            flash(message, 'error')
            return redirect('/login')
        
        try:
            cur = mysql.connection.cursor()
            
            # Check worker_login credentials (username or email from workers table)
            cur.execute("""
                SELECT wl.login_id, wl.worker_id, wl.username, wl.password, w.name, w.email, w.profession, w.deptName
                FROM worker_login wl
                JOIN workers w ON wl.worker_id = w.worker_id
                WHERE (wl.username = %s OR w.email = %s)
            """, (username_or_email, username_or_email))
            
            user = cur.fetchone()
            
            if user and check_password_hash(user[3], password):
                # Clear failed login attempts
                clear_login_attempts(username_or_email)
                
                # Get worker's allowed pages
                cur.execute("""
                    SELECT pages FROM worker_page_permissions 
                    WHERE worker_id = %s
                """, (user[1],))
                allowed_pages = [row[0] for row in cur.fetchall()]
                cur.close()
                
                # Set session variables with permanent session
                session.permanent = True
                session['logged_in'] = True
                session['login_id'] = user[0]
                session['worker_id'] = user[1]
                session['username'] = user[2]
                session['name'] = user[4]
                session['email'] = user[5]
                session['profession'] = user[6]
                session['department'] = user[7]
                session['allowed_pages'] = allowed_pages
                
                flash(f'Welcome back, {user[4]}!', 'success')
                
                # Redirect to next URL if exists, otherwise to first allowed page
                if next_url and next_url.startswith('/'):
                    return redirect(next_url)
                elif allowed_pages:
                    first_page = allowed_pages[0]
                    return redirect(f'/{first_page}')
                else:
                    return redirect('/access-denied')
            else:
                cur.close()
                # Record failed attempt
                record_failed_attempt(username_or_email)
                remaining_attempts = MAX_LOGIN_ATTEMPTS - login_attempts.get(username_or_email, [0, None])[0]
                if remaining_attempts > 0:
                    flash(f'Invalid username/email or password. {remaining_attempts} attempts remaining.', 'error')
                else:
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                return redirect('/login')
                
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Login error: {e}")
            print(f"Error type: {type(e).__name__}")
            print(f"Full traceback:\n{error_details}")
            flash(f'Database connection error. Please contact administrator.', 'error')
            return redirect('/login')
    
    # GET request - show login form
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset with email-sent reset code"""
    if request.method == 'POST':
        action = request.form.get('action', 'send_code')
        
        # Step 1: Send reset code to email
        if action == 'send_code':
            email = request.form.get('email', '').strip().lower()
            
            if not email:
                flash('Email is required', 'error')
                return render_template('forgot_password.html')
            
            # Validate email format
            is_valid_email, email_error = validate_email(email)
            if not is_valid_email:
                flash(f'Invalid email: {email_error}', 'error')
                return render_template('forgot_password.html')
            
            try:
                cur = mysql.connection.cursor()
                
                # Find worker by email
                cur.execute("""
                    SELECT wl.worker_id, wl.username, w.email, w.name
                    FROM worker_login wl
                    JOIN workers w ON wl.worker_id = w.worker_id
                    WHERE w.email = %s
                """, (email,))
                
                worker = cur.fetchone()
                cur.close()
                
                if not worker:
                    # Email not found in workers database
                    flash('This email is not registered in our system. Please check your email or contact support.', 'error')
                    return render_template('forgot_password.html')
                
                worker_id, username, worker_email, name = worker
                
                # Generate 6-digit random code
                reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
                
                # Store reset code with expiration
                password_reset_codes[email] = {
                    'code': reset_code,
                    'expires': datetime.now() + RESET_CODE_EXPIRATION,
                    'worker_id': worker_id,
                    'username': username,
                    'name': name
                }
                
                # Send email with reset code
                try:
                    msg = Message(
                        subject='Your Dashboard Account - Password Reset Verification Code',
                        recipients=[worker_email],
                        sender=('Dashboard Security', app.config['MAIL_USERNAME'])
                    )
                    msg.html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <style>
                            body {{ 
                                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; 
                                line-height: 1.6; 
                                color: #333333;
                                background-color: #f5f5f5;
                                margin: 0;
                                padding: 0;
                            }}
                            .email-wrapper {{ 
                                max-width: 600px; 
                                margin: 40px auto; 
                                background-color: #ffffff;
                                border: 1px solid #e0e0e0;
                                border-radius: 8px;
                                overflow: hidden;
                            }}
                            .header {{ 
                                background-color: #228B22;
                                color: #ffffff; 
                                padding: 30px 40px; 
                                text-align: left;
                            }}
                            .header h1 {{ 
                                margin: 0;
                                font-size: 24px;
                                font-weight: 600;
                                letter-spacing: -0.5px;
                            }}
                            .header p {{
                                margin: 8px 0 0 0;
                                font-size: 14px;
                                opacity: 0.9;
                            }}
                            .content {{ 
                                padding: 40px; 
                                background-color: #ffffff;
                            }}
                            .content p {{
                                margin: 0 0 16px 0;
                                color: #555555;
                                font-size: 15px;
                            }}
                            .code-container {{
                                background-color: #f8f9fa;
                                border: 2px solid #228B22;
                                border-radius: 8px;
                                padding: 24px;
                                margin: 30px 0;
                                text-align: center;
                            }}
                            .code-label {{
                                font-size: 13px;
                                color: #666666;
                                margin-bottom: 12px;
                                text-transform: uppercase;
                                letter-spacing: 1px;
                                font-weight: 600;
                            }}
                            .code {{ 
                                font-size: 36px; 
                                font-weight: 700; 
                                color: #228B22; 
                                letter-spacing: 8px;
                                font-family: 'Courier New', monospace;
                            }}
                            .info-box {{ 
                                background-color: #fff8e1; 
                                border-left: 4px solid #ffa726; 
                                padding: 16px 20px; 
                                margin: 24px 0;
                                border-radius: 4px;
                            }}
                            .info-box p {{
                                margin: 0;
                                color: #5d4037;
                                font-size: 14px;
                            }}
                            .footer {{ 
                                background-color: #f8f9fa;
                                padding: 24px 40px;
                                text-align: center;
                                border-top: 1px solid #e0e0e0;
                            }}
                            .footer p {{ 
                                color: #888888; 
                                font-size: 13px;
                                margin: 0 0 8px 0;
                            }}
                            .company-name {{
                                color: #228B22;
                                font-weight: 600;
                            }}
                        </style>
                    </head>
                    <body>
                        <div class="email-wrapper">
                            <div class="header">
                                <h1>Password Reset Request</h1>
                                <p>Dashboard Security Team</p>
                            </div>
                            <div class="content">
                                <p>Hello <strong>{name}</strong>,</p>
                                <p>We received a request to reset your password for your Dashboard account. To proceed with the password reset, please use the verification code below:</p>
                                
                                <div class="code-container">
                                    <div class="code-label">Your Verification Code</div>
                                    <div class="code">{reset_code}</div>
                                </div>
                                
                                <div class="info-box">
                                    <p><strong>Security Notice:</strong> This code will expire in 15 minutes for your security. Do not share this code with anyone.</p>
                                </div>
                                
                                <p>If you did not request a password reset, please disregard this email. Your account remains secure and no changes have been made.</p>
                                
                                <p style="margin-top: 32px;">Best regards,<br><span class="company-name">Dashboard Security Team</span></p>
                            </div>
                            <div class="footer">
                                <p>This is an automated security notification from Dashboard.</p>
                                <p>&copy; 2025 Dashboard. All rights reserved.</p>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    mail.send(msg)
                    flash('Reset code sent to your email! Check your inbox.', 'success')
                    return render_template('forgot_password.html', email_sent=True, email=email)
                except Exception as e:
                    import traceback
                    print(f"Email send error: {e}")
                    print(f"Email error traceback:\n{traceback.format_exc()}")
                    
                    # Provide specific error messages
                    error_msg = str(e).lower()
                    if 'authentication' in error_msg or 'password' in error_msg or '535' in error_msg:
                        flash('Email authentication failed. Please check email configuration.', 'error')
                    elif 'connection' in error_msg or 'timeout' in error_msg:
                        flash('Could not connect to email server. Please try again.', 'error')
                    else:
                        flash(f'Error sending email: {str(e)}. Please try again or contact support.', 'error')
                    return render_template('forgot_password.html')
                    
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                print(f"Password reset error: {e}")
                print(f"Full traceback:\n{error_details}")
                
                # Provide more helpful error messages
                if 'Connection' in str(e) or 'connection' in str(e):
                    flash('Database connection error. Please try again or contact support.', 'error')
                elif 'MySQLdb' in str(e):
                    flash('Database error. Please try again or contact support.', 'error')
                else:
                    flash(f'An error occurred: {str(e)}. Please try again or contact support.', 'error')
                return render_template('forgot_password.html')
        
        # Step 2: Verify code and reset password
        elif action == 'reset_password':
            email = request.form.get('email', '').strip().lower()
            reset_code = request.form.get('reset_code', '').strip()
            new_password = request.form.get('new_password', '').strip()
            confirm_password = request.form.get('confirm_password', '').strip()
            
            # Validation
            if not all([email, reset_code, new_password, confirm_password]):
                flash('All fields are required', 'error')
                return render_template('forgot_password.html', email_sent=True, email=email)
            
            if new_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('forgot_password.html', email_sent=True, email=email)
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters', 'error')
                return render_template('forgot_password.html', email_sent=True, email=email)
            
            # Validate password strength
            if not PASSWORD_REGEX.match(new_password):
                flash('Password must contain: uppercase, lowercase, number, and special character', 'error')
                return render_template('forgot_password.html', email_sent=True, email=email)
            
            # Check if reset code exists and is valid
            if email not in password_reset_codes:
                flash('Invalid or expired reset code. Please request a new one.', 'error')
                return render_template('forgot_password.html')
            
            reset_data = password_reset_codes[email]
            
            # Check if code expired
            if datetime.now() > reset_data['expires']:
                del password_reset_codes[email]
                flash('Reset code has expired. Please request a new one.', 'error')
                return render_template('forgot_password.html')
            
            # Verify code
            if reset_code != reset_data['code']:
                flash('Invalid reset code. Please check and try again.', 'error')
                return render_template('forgot_password.html', email_sent=True, email=email)
            
            # Update password
            try:
                cur = mysql.connection.cursor()
                new_hash = generate_password_hash(new_password)
                cur.execute("""
                    UPDATE worker_login 
                    SET password = %s 
                    WHERE worker_id = %s
                """, (new_hash, reset_data['worker_id']))
                
                mysql.connection.commit()
                cur.close()
                
                # Delete used reset code
                del password_reset_codes[email]
                
                flash('Password reset successfully! You can now login with your new password.', 'success')
                return redirect('/login')
                
            except Exception as e:
                print(f"Password update error: {e}")
                flash('Error updating password. Please try again.', 'error')
                return render_template('forgot_password.html', email_sent=True, email=email)
    
    # GET request
    return render_template('forgot_password.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per hour")  # Rate limit registration attempts
def register():
    """Worker registration - only workers can register"""
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not all([email, username, password]):
            flash('Email, username, and password are required', 'error')
            return redirect('/login')
        
        # Validate email format and legitimacy
        is_valid_email, email_error = validate_email(email)
        if not is_valid_email:
            flash(f'Email validation failed: {email_error}', 'error')
            return redirect('/login')
        
        # Validate password strength
        if not PASSWORD_REGEX.match(password):
            flash('Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character', 'error')
            return redirect('/login')
        
        try:
            cur = mysql.connection.cursor()
            
            # Check if email exists in workers table
            cur.execute("SELECT worker_id, name, phone FROM workers WHERE email = %s", (email.strip().lower(),))
            worker = cur.fetchone()
            
            if not worker:
                cur.close()
                flash('This email is not authorized to register on this dashboard. Please contact the administrator.', 'error')
                return redirect('/login')
            
            worker_id, worker_name, worker_phone = worker
            
            # Check if worker already has login credentials
            cur.execute("SELECT login_id FROM worker_login WHERE worker_id = %s", (worker_id,))
            if cur.fetchone():
                cur.close()
                flash('Worker already registered. Please login instead.', 'error')
                return redirect('/login')
            
            # Check if username already taken
            cur.execute("SELECT username FROM worker_login WHERE username = %s", (username,))
            if cur.fetchone():
                cur.close()
                flash('Username already taken. Please choose another.', 'error')
                return redirect('/login')
            
            # Hash password and create login credentials
            password_hash = generate_password_hash(password)
            cur.execute("""
                INSERT INTO worker_login (worker_id, username, password, created_at)
                VALUES (%s, %s, %s, NOW())
            """, (worker_id, username, password_hash))
            
            mysql.connection.commit()
            login_id = cur.lastrowid
            
            # Get worker's allowed pages
            cur.execute("""
                SELECT pages FROM worker_page_permissions 
                WHERE worker_id = %s
            """, (worker_id,))
            allowed_pages = [row[0] for row in cur.fetchall()]
            cur.close()
            
            # Auto-login after registration
            session['logged_in'] = True
            session['login_id'] = login_id
            session['worker_id'] = worker_id
            session['username'] = username
            session['name'] = worker_name
            session['email'] = email
            session['phone'] = worker_phone
            session['allowed_pages'] = allowed_pages
            
            flash(f'Registration successful! Welcome {worker_name}!', 'success')
            return redirect('/')
            
        except Exception as e:
            print(f"Registration error: {e}")
            flash(f'Registration error: {str(e)}', 'error')
            return redirect('/login')
    
    # GET request - redirect to login page
    return redirect('/login')

@app.route('/api/my-permissions')
@login_required
def my_permissions():
    """API endpoint to check current worker's allowed pages"""
    if 'worker_id' not in session:
        return jsonify({'ok': False, 'error': 'Not logged in as worker'}), 401
    
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT pages FROM worker_page_permissions 
            WHERE worker_id = %s
        """, (session['worker_id'],))
        allowed_pages = [row[0] for row in cur.fetchall()]
        cur.close()
        
        return jsonify({
            'ok': True,
            'worker_id': session['worker_id'],
            'username': session.get('username'),
            'name': session.get('name'),
            'allowed_pages': allowed_pages
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# ============================================================================
# PROFIT MARGIN CALCULATOR - DISABLED
# ============================================================================
# @app.route('/profit-analysis')
# @login_required
# @check_page_permission('reports')
# @cache.cached(timeout=300)  # Cache for 5 minutes
# def profit_analysis():
#     """Profit margin analysis dashboard - optimized"""
#     try:
#         cur = mysql.connection.cursor()
#         
#         # Get products with profit calculations (indexed query)
#         query = """
#             SELECT 
#                 id,
#                 name,
#                 price,
#                 cost_of_goods,
#                 stock,
#                 category_id,
#                 image,
#                 (price - cost_of_goods) as profit_per_unit,
#                 CASE 
#                     WHEN cost_of_goods > 0 THEN ((price - cost_of_goods) / cost_of_goods * 100)
#                     ELSE 0
#                 END as profit_margin_percent,
#                 (price - cost_of_goods) * stock as total_potential_profit
#             FROM products
#             WHERE cost_of_goods > 0
#             ORDER BY profit_margin_percent DESC
#             LIMIT 100
#         """
#         cur.execute(query)
#         products = cur.fetchall()
#         
#         # Summary statistics
#         cur.execute("""
#             SELECT 
#                 COUNT(*) as total_products,
#                 SUM(price - cost_of_goods) as total_profit_if_sold_all,
#                 AVG(CASE WHEN cost_of_goods > 0 THEN ((price - cost_of_goods) / cost_of_goods * 100) ELSE 0 END) as avg_margin
#             FROM products
#             WHERE cost_of_goods > 0
#         """)
#         summary = cur.fetchone()
#         
#         # Top 5 most profitable
#         cur.execute("""
#             SELECT name, (price - cost_of_goods) as profit
#             FROM products
#             WHERE cost_of_goods > 0
#             ORDER BY profit DESC
#             LIMIT 5
#         """)
#         top_profitable = cur.fetchall()
#         
#         # Top 5 least profitable (potential losses)
#         cur.execute("""
#             SELECT name, (price - cost_of_goods) as profit
#             FROM products
#             WHERE cost_of_goods > 0
#             ORDER BY profit ASC
#             LIMIT 5
#         """)
#         least_profitable = cur.fetchall()
#         
#         cur.close()
#         
#         return render_template('profit_analysis.html',
#                              products=products,
#                              summary=summary,
#                              top_profitable=top_profitable,
#                              least_profitable=least_profitable)
#     except Exception as e:
#         flash(f'Error loading profit analysis: {str(e)}', 'error')
#         return redirect('/dashboard')

# ============================================================================
# BANNER MANAGEMENT - DISABLED
# ============================================================================
# @app.route('/banners')
# @login_required
# @check_page_permission('products')
# def banners_management():
#     """Banner management dashboard"""
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("SELECT baner_id, baner_name, banner_image FROM banners ORDER BY baner_id DESC")
#         banners = cur.fetchall()
#         cur.close()
#         return render_template('banners.html', banners=banners)
#     except Exception as e:
#         flash(f'Error loading banners: {str(e)}', 'error')
#         return redirect('/dashboard')

# @app.route('/api/banners/add', methods=['POST'])
# @login_required
# @check_page_permission('products')
# def add_banner():
#     """Add new banner"""
#     try:
#         name = request.form.get('name')
#         image_url = request.form.get('image_url')
#         
#         if not name or not image_url:
#             return jsonify({'ok': False, 'error': 'Name and image URL required'}), 400
#         
#         cur = mysql.connection.cursor()
#         cur.execute("INSERT INTO banners (baner_name, banner_image) VALUES (%s, %s)", (name, image_url))
#         mysql.connection.commit()
#         banner_id = cur.lastrowid
#         cur.close()
#         
#         return jsonify({'ok': True, 'banner_id': banner_id})
#     except Exception as e:
#         return jsonify({'ok': False, 'error': str(e)}), 500

# @app.route('/api/banners/update/<int:banner_id>', methods=['POST'])
# @login_required
# @check_page_permission('products')
# def update_banner(banner_id):
#     """Update banner"""
#     try:
#         name = request.form.get('name')
#         image_url = request.form.get('image_url')
#         
#         cur = mysql.connection.cursor()
#         cur.execute("UPDATE banners SET baner_name = %s, banner_image = %s WHERE baner_id = %s", 
#                    (name, image_url, banner_id))
#         mysql.connection.commit()
#         cur.close()
#         
#         return jsonify({'ok': True})
#     except Exception as e:
#         return jsonify({'ok': False, 'error': str(e)}), 500

# @app.route('/api/banners/delete/<int:banner_id>', methods=['POST'])
# @login_required
# @check_page_permission('products')
# def delete_banner(banner_id):
#     """Delete banner"""
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM banners WHERE baner_id = %s", (banner_id,))
#         mysql.connection.commit()
#         cur.close()
#         
#         return jsonify({'ok': True})
#     except Exception as e:
#         return jsonify({'ok': False, 'error': str(e)}), 500

# ============================================================================
# BUSINESS LOCATION & DELIVERY MAP - Route optimization
# ============================================================================
@app.route('/business-settings')
@login_required
@check_page_permission('dashboard')  # Admin only
def business_settings():
    """Business location settings"""
    try:
        # Get current business location from environment or database
        business_lat = os.getenv('BUSINESS_LATITUDE', '-1.9441')  # Default: Kigali
        business_lng = os.getenv('BUSINESS_LONGITUDE', '30.0619')
        business_address = os.getenv('BUSINESS_ADDRESS', 'Kigali, Rwanda')
        
        return render_template('business_settings.html',
                             business_lat=business_lat,
                             business_lng=business_lng,
                             business_address=business_address)
    except Exception as e:
        flash(f'Error loading settings: {str(e)}', 'error')
        return redirect('/dashboard')

@app.route('/api/business-location/update', methods=['POST'])
@login_required
@check_page_permission('dashboard')
def update_business_location():
    """Update business location"""
    try:
        data = request.json
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        address = data.get('address', '')
        
        if not latitude or not longitude:
            return jsonify({'ok': False, 'error': 'Latitude and longitude required'}), 400
        
        # Store in session for now (in production, save to database or .env)
        session['business_latitude'] = latitude
        session['business_longitude'] = longitude
        session['business_address'] = address
        
        return jsonify({'ok': True, 'message': 'Business location updated'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

# LOCATION APIS - DISABLED
# @app.route('/api/set-current-location', methods=['POST'])
# @login_required
# @csrf.exempt
# def set_current_location():
#     """Save user's current location to session"""
#     try:
#         data = request.get_json()
#         latitude = data.get('latitude')
#         longitude = data.get('longitude')
#         
#         if not latitude or not longitude:
#             return jsonify({'ok': False, 'error': 'Latitude and longitude required'}), 400
#         
#         # Save to session
#         session['current_latitude'] = float(latitude)
#         session['current_longitude'] = float(longitude)
#         session.permanent = True
#         
#         return jsonify({'ok': True, 'message': 'Location saved successfully'})
#     except Exception as e:
#         return jsonify({'ok': False, 'error': str(e)}), 500

# @app.route('/api/get-current-location')
# @login_required
# def get_current_location():
#     """Get user's current location from session"""
#     try:
#         lat = session.get('current_latitude')
#         lng = session.get('current_longitude')
#         
#         return jsonify({
#             'ok': True,
#             'latitude': lat,
#             'longitude': lng,
#             'has_location': lat is not None and lng is not None
#         })
#     except Exception as e:
#         return jsonify({'ok': False, 'error': str(e)}), 500

# DELIVERY MAP - DISABLED
# @app.route('/delivery-map')
# @login_required
# @check_page_permission('orders')
# def delivery_map():
#     """Delivery routes map with optimization"""
#     try:
#         # Use current location if available, otherwise use business location
#         current_lat = session.get('current_latitude')
#         current_lng = session.get('current_longitude')
#         
#         if current_lat and current_lng:
#             start_lat = float(current_lat)
#             start_lng = float(current_lng)
#             location_type = 'current'
#         else:
#             start_lat = float(session.get('business_latitude', os.getenv('BUSINESS_LATITUDE', '-1.9441')))
#             start_lng = float(session.get('business_longitude', os.getenv('BUSINESS_LONGITUDE', '30.0619')))
#             location_type = 'business'
#         
#         # Get pending/processing orders with locations (optimized query)
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             SELECT 
#                 id,
#                 full_name,
#                 address_line,
#                 city,
#                 delivery_phone,
#                 latitude,
#                 longitude,
#                 total_amount,
#                 status,
#                 created_at
#             FROM orders
#             WHERE status IN ('pending', 'processing', 'shipped')
#               AND latitude IS NOT NULL 
#               AND longitude IS NOT NULL
#             ORDER BY created_at DESC
#             LIMIT 50
#         """)
#         orders = cur.fetchall()
#         cur.close()
#         
#         return render_template('delivery_map.html',
#                              orders=orders,
#                              start_lat=start_lat,
#                              start_lng=start_lng,
#                              location_type=location_type)
#     except Exception as e:
#         flash(f'Error loading delivery map: {str(e)}', 'error')
#         return redirect('/orders')

# @app.route('/api/delivery-route/<int:order_id>')
# @login_required
# @check_page_permission('orders')
# def get_delivery_route(order_id):
#     """Get route from current/business location to order location"""
#     try:
#         # Use current location if available, otherwise use business location
#         current_lat = session.get('current_latitude')
#         current_lng = session.get('current_longitude')
#         
#         if current_lat and current_lng:
#             start_lat = float(current_lat)
#             start_lng = float(current_lng)
#         else:
#             start_lat = float(session.get('business_latitude', os.getenv('BUSINESS_LATITUDE', '-1.9441')))
#             start_lng = float(session.get('business_longitude', os.getenv('BUSINESS_LONGITUDE', '30.0619')))
#         
#         # Get order location
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             SELECT latitude, longitude, address_line, full_name
#             FROM orders
#             WHERE id = %s AND latitude IS NOT NULL AND longitude IS NOT NULL
#         """, (order_id,))
#         order = cur.fetchone()
#         cur.close()
#         
#         if not order:
#             return jsonify({'ok': False, 'error': 'Order location not found'}), 404
#         
#         order_lat, order_lng, address, customer_name = order
#         
#         # Calculate straight-line distance (in km)
#         from math import radians, sin, cos, sqrt, atan2
#         R = 6371  # Earth's radius in km
#         
#         lat1, lon1 = radians(start_lat), radians(start_lng)
#         lat2, lon2 = radians(float(order_lat)), radians(float(order_lng))
#         
#         dlat = lat2 - lat1
#         dlon = lon2 - lon1
#         
#         a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
#         c = 2 * atan2(sqrt(a), sqrt(1-a))
#         distance = R * c
#         
#         return jsonify({
#             'ok': True,
#             'route': {
#                 'start': {'lat': start_lat, 'lng': start_lng},
#                 'end': {'lat': float(order_lat), 'lng': float(order_lng)},
#                 'distance_km': round(distance, 2),
#                 'customer_name': customer_name,
#                 'address': address
#             }
#         })
#     except Exception as e:
#         return jsonify({'ok': False, 'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

