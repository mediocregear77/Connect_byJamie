from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from admin_console.config import Config, verify_admin_login
import logging
from dotenv import load_dotenv
import pyotp
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/admin_console.log')
    ]
)
logger = logging.getLogger(__name__)

auth_blueprint = Blueprint('auth', __name__, template_folder='templates')

# Flask-Login setup
login_manager = LoginManager()

class AdminUser(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return AdminUser(username) if verify_admin_login(username, None, check_exists=True) else None

@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    load_dotenv()
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        totp_code = request.form.get('totp_code', '')

        if not username or not password:
            flash('Username and password are required.', 'danger')
            logger.warning(f"Login attempt with missing credentials: username={username}")
            return render_template('login.html')

        try:
            if verify_admin_login(username, password):
                # Verify TOTP (MFA)
                totp_secret = os.getenv(f'TOTP_SECRET_{username}', '')
                if not totp_secret or not pyotp.TOTP(totp_secret).verify(totp_code):
                    flash('Invalid MFA code.', 'danger')
                    logger.warning(f"Invalid MFA for username={username}")
                    return render_template('login.html')

                user = AdminUser(username)
                login_user(user)
                logger.info(f"Successful login: username={username}")
                return redirect(url_for('dashboard.index'))
            else:
                flash('Invalid credentials.', 'danger')
                logger.warning(f"Failed login attempt: username={username}")
                return render_template('login.html')
        except Exception as e:
            flash('Login error.', 'danger')
            logger.error(f"Login error for username={username}: {e}")
            return render_template('login.html'), 500
    return render_template('login.html')

@auth_blueprint.route('/logout')
@login_required
def logout():
    try:
        username = load_user(getattr(load_user, 'id', None)).id
        logout_user()
        logger.info(f"Successful logout: username={username}")
        return redirect(url_for('auth.login'))
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return redirect(url_for('auth.login')), 500

# Initialize login manager with app
def init_auth(app):
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'