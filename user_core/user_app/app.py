from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
import logging
from dotenv import load_dotenv
import os
import pyotp
from user_core.user_app.auth import authenticate_user
from user_core.user_app.dashboard import user_dashboard
from user_core.user_app.config import USER_APP_SECRET_KEY

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/user_app.log')
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = USER_APP_SECRET_KEY

# Enforce security headers
Talisman(app, force_https=True, strict_transport_security=True)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if authenticate_user(username, None, check_exists=True) else None

# Login form with CSRF protection
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    totp_code = StringField('MFA Code', validators=[DataRequired()])

@app.route("/", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            username = form.username.data.strip()
            password = form.password.data
            totp_code = form.totp_code.data

            if authenticate_user(username, password):
                # Verify TOTP (MFA)
                totp_secret = os.getenv(f'TOTP_SECRET_{username}', '')
                if not totp_secret or not pyotp.TOTP(totp_secret).verify(totp_code):
                    logger.warning(f"Invalid MFA for username={username}")
                    return render_template('login.html', form=form, error="Invalid MFA code.")

                user = User(username)
                login_user(user)
                logger.info(f"Successful login: username={username}")
                return redirect(url_for("dashboard"))
            else:
                logger.warning(f"Failed login attempt: username={username}")
                return render_template('login.html', form=form, error="Invalid credentials.")
        except Exception as e:
            logger.error(f"Login error for username={username}: {e}")
            return render_template('login.html', form=form, error="Internal server error."), 500
    return render_template('login.html', form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    try:
        user = load_user(getattr(load_user, 'id', None)).id
        dashboard_data = user_dashboard(user)
        logger.info(f"Dashboard accessed: username={user}")
        return dashboard_data
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('error.html', error="Unable to load dashboard"), 500

@app.route("/logout")
@login_required
def logout():
    try:
        username = load_user(getattr(load_user, 'id', None)).id
        logout_user()
        logger.info(f"Successful logout: username={username}")
        return redirect(url_for("login"))
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return redirect(url_for("login")), 500

@app.errorhandler(404)
def not_found(e):
    logger.warning(f"404 error: {e}")
    return render_template('error.html', error="Page not found"), 404

if __name__ == "__main__":
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 8080))
    app.run(host=host, port=port, debug=False)