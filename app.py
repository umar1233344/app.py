import os
import secrets
import hashlib
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, redirect, url_for,
    render_template_string, make_response, flash
)

from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)

from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape


# ==========================================
# CONFIGURATION
# ==========================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "CHANGE-THIS-TO-A-LONG-RANDOM-SECRET"
)

database_url = os.environ.get(
    "DATABASE_URL", "sqlite:///adnova.db"
)

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "false").lower() == "true"
)

db = SQLAlchemy(app)

csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# ==========================================
# DATABASE
# ==========================================

class Device(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    device_hash = db.Column(
        db.String(64), unique=True, nullable=False
    )

    extra_slots = db.Column(
        db.Integer, default=0, nullable=False
    )


class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(50), unique=True, nullable=False
    )

    email = db.Column(
        db.String(120), unique=True, nullable=False
    )

    password = db.Column(
        db.String(255), nullable=False
    )

    device_hash = db.Column(
        db.String(64), nullable=False
    )

    balance = db.Column(
        db.Float, default=0
    )

    is_admin = db.Column(
        db.Boolean, default=False
    )

    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )


class Activity(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer, nullable=False
    )

    action = db.Column(
        db.String(200), nullable=False
    )

    created_at = db.Column(
        db.DateTime, default=datetime.utcnow
    )


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ==========================================
# SECURITY FUNCTIONS
# ==========================================

def hash_device(token):
    return hashlib.sha256(
        token.encode()
    ).hexdigest()


def get_device_token():
    return request.cookies.get("adnova_device")


def log_activity(user_id, action):

    db.session.add(
        Activity(
            user_id=user_id,
            action=action
        )
    )

    db.session.commit()


def admin_required(function):

    @wraps(function)
    @login_required
    def wrapper(*args, **kwargs):

        if not current_user.is_admin:
            flash("Admin permission required.")
            return redirect(url_for("dashboard"))

        return function(*args, **kwargs)

    return wrapper


# ==========================================
# PREMIUM DESIGN
# ==========================================

PAGE = """
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1">

<title>{{ title }} | ADNOVA</title>

<style>

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    min-height: 100vh;
    font-family: Arial, sans-serif;
    color: white;

    background: linear-gradient(
        -45deg,
        #070817,
        #171034,
        #101b35,
        #090b1d
    );

    background-size: 400% 400%;
    animation: gradient 15s ease infinite;
    overflow-x: hidden;
}

@keyframes gradient {
    0% {background-position: 0% 50%;}
    50% {background-position: 100% 50%;}
    100% {background-position: 0% 50%;}
}

.orb {
    position: fixed;
    width: 250px;
    height: 250px;
    border-radius: 50%;
    filter: blur(100px);
    opacity: .22;
    pointer-events: none;
    z-index: -1;
}

.orb.one {
    background: #7b45ff;
    top: 5%;
    left: -100px;
}

.orb.two {
    background: #00d9ff;
    right: -100px;
    bottom: 5%;
}

.navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px 7%;
    border-bottom: 1px solid #ffffff15;
    background: #090d1c88;
    backdrop-filter: blur(20px);
}

.logo {
    font-size: 25px;
    font-weight: bold;
    letter-spacing: 3px;
    color: #69eaff;
    text-shadow: 0 0 20px #398cff;
}

.navlinks a {
    margin-left: 15px;
    color: #c9d5f7;
    text-decoration: none;
    font-size: 13px;
}

.navlinks a:hover {
    color: #65e6ff;
}

.container {
    width: 92%;
    max-width: 1100px;
    margin: 45px auto;
}

.box {
    max-width: 460px;
    margin: 45px auto;
    padding: 30px;
    border: 1px solid #ffffff20;
    border-radius: 24px;
    background: #ffffff0c;
    backdrop-filter: blur(25px);
    box-shadow: 0 20px 70px #00000055;
    animation: appear .7s ease;
}

@keyframes appear {
    from {
        opacity: 0;
        transform: translateY(25px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

h1 {
    font-size: 34px;
    color: #72edff;
    text-shadow: 0 0 20px #398cff66;
    margin-bottom: 18px;
}

h2 {
    font-size: 24px;
    margin-bottom: 12px;
}

h3 {
    color: #b9caff;
    margin-bottom: 12px;
}

p {
    color: #b9c5dc;
    line-height: 1.7;
}

input {
    width: 100%;
    padding: 15px;
    margin: 10px 0;
    border-radius: 12px;
    border: 1px solid #ffffff20;
    background: #10172d;
    color: white;
    outline: none;
}

input:focus {
    border-color: #65e6ff;
    box-shadow: 0 0 15px #397cff66;
}

button, .button {
    display: inline-block;
    width: 100%;
    padding: 15px;
    margin-top: 12px;
    border: none;
    border-radius: 12px;
    background: linear-gradient(
        100deg,
        #7554ff,
        #20c9ed
    );
    color: white;
    font-weight: bold;
    text-align: center;
    text-decoration: none;
    cursor: pointer;
    transition: .3s;
}

button:hover, .button:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 25px #635bff77;
}

button:disabled {
    opacity: .5;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
}

.card {
    padding: 23px;
    margin: 15px 0;
    border: 1px solid #ffffff18;
    border-radius: 18px;
    background: linear-gradient(
        135deg,
        #ffffff12,
        #ffffff04
    );
    transition: .3s;
}

.card:hover {
    transform: translateY(-5px);
    border-color: #65e6ff88;
    box-shadow: 0 10px 30px #287dff22;
}

.grid {
    display: grid;
    grid-template-columns:
    repeat(auto-fit, minmax(220px, 1fr));
    gap: 15px;
}

.balance {
    font-size: 32px;
    color: #65e6ff;
    font-weight: bold;
    margin-top: 10px;
}

a {
    color: #65e6ff;
    text-decoration: none;
}

.alert {
    padding: 13px;
    margin-bottom: 15px;
    background: #ffffff12;
    border-radius: 10px;
    color: #a9eaff;
}

.small {
    font-size: 12px;
    color: #8d9bb9;
}

.footer {
    text-align: center;
    padding: 25px;
    color: #8793ae;
    font-size: 12px;
}

@media(max-width:600px) {

    .navbar {
        padding: 18px 5%;
        flex-direction: column;
        gap: 15px;
    }

    .navlinks a {
        margin: 0 6px;
    }

    .container {
        margin: 25px auto;
    }

    .box {
        padding: 22px;
    }
}

</style>

</head>

<body>

<div class="orb one"></div>
<div class="orb two"></div>

<header class="navbar">

<div class="logo">ADNOVA</div>

<div class="navlinks">

{% if logged_in %}

<a href="/dashboard">Dashboard</a>
<a href="/profile">Profile</a>
<a href="/activity">Activity</a>
<a href="/logout">Logout</a>

{% else %}

<a href="/">Home</a>
<a href="/login">Login</a>
<a href="/register">Register</a>

{% endif %}

</div>

</header>

{% with messages = get_flashed_messages() %}

{% if messages %}

<div class="container">

{% for message in messages %}

<div class="alert">{{ message }}</div>

{% endfor %}

</div>

{% endif %}

{% endwith %}

<div class="container">

{{ content|safe }}

</div>

<div class="footer">
ADNOVA © 2026 | Watch Ads. Earn Rewards.
</div>

</body>
</html>
"""


# ==========================================
# PAGE RENDERER - CSRF FIX
# ==========================================

def render_page(content, title="ADNOVA"):

    token = generate_csrf()

    content = content.replace(
        "__CSRF_TOKEN__",
        token
    )

    return render_template_string(
        PAGE,
        content=content,
        title=title,
        logged_in=current_user.is_authenticated
    )


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    content = """
    <div class="box">

        <h1 style="text-align:center">
            ADNOVA
        </h1>

        <p style="text-align:center">
            Watch Ads. Earn Rewards.
        </p>

        <div class="card">

            <h2>Welcome to ADNOVA</h2>

            <p>
                A modern rewards platform
                with a premium experience.
            </p>

        </div>

        <a class="button" href="/register">
            CREATE ACCOUNT
        </a>

        <a class="button" href="/login">
            LOGIN
        </a>

    </div>
    """

    return render_page(content, "Home")


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        if len(username) < 3 or len(username) > 50:
            flash("Username must be 3-50 characters.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return redirect(url_for("register"))

        token = get_device_token()

        if not token:
            token = secrets.token_urlsafe(32)

        device_hash = hash_device(token)

        device = Device.query.filter_by(
            device_hash=device_hash
        ).first()

        if not device:

            device = Device(
                device_hash=device_hash,
                extra_slots=0
            )

            db.session.add(device)
            db.session.flush()

        existing = User.query.filter_by(
            device_hash=device_hash
        ).count()

        allowed_accounts = 2 + device.extra_slots

        if existing >= allowed_accounts:

            db.session.rollback()

            flash(
                "Device account limit reached. "
                "Contact administrator."
            )

            return redirect(url_for("register"))

        admin_email = os.environ.get(
            "ADMIN_EMAIL", ""
        ).strip().lower()

        is_admin = bool(
            admin_email and email == admin_email
        )

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            device_hash=device_hash,
            is_admin=is_admin
        )

        db.session.add(user)
        db.session.commit()

        login_user(user)

        log_activity(
            user.id,
            "Account registered"
        )

        response = make_response(
            redirect(url_for("dashboard"))
        )

        response.set_cookie(
            "adnova_device",
            token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=app.config["SESSION_COOKIE_SECURE"],
            samesite="Lax"
        )

        return response

    content = """
    <div class="box">

        <h1>Create Account</h1>

        <p>Join the ADNOVA community.</p>

        <form method="POST">

            <input type="hidden"
            name="csrf_token"
            value="__CSRF_TOKEN__">

            <input
                name="username"
                placeholder="Username"
                required
                minlength="3"
                maxlength="50"
            >

            <input
                name="email"
                type="email"
                placeholder="Email Address"
                required
            >

            <input
                name="password"
                type="password"
                placeholder="Password (minimum 8 characters)"
                required
                minlength="8"
            >

            <button type="submit">
                CREATE ACCOUNT
            </button>

        </form>

        <p style="margin-top:20px">
            Already registered?
            <a href="/login">Login</a>
        </p>

    </div>
    """

    return render_page(content, "Register")


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password, password
        ):

            login_user(user)

            log_activity(
                user.id,
                "Logged in"
            )

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

        return redirect(url_for("login"))

    content = """
    <div class="box">

        <h1>Welcome Back</h1>

        <p>Login to your ADNOVA account.</p>

        <form method="POST">

            <input type="hidden"
            name="csrf_token"
            value="__CSRF_TOKEN__">

            <input
                type="email"
                name="email"
                placeholder="Email Address"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Password"
                required
            >

            <button type="submit">
                LOGIN
            </button>

        </form>

        <p style="margin-top:20px">
            New here?
            <a href="/register">Create Account</a>
        </p>

    </div>
    """

    return render_page(content, "Login")


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    admin_link = ""

    if current_user.is_admin:

        admin_link = """
        <div class="card">

            <h3>Administrator</h3>

            <p>Manage users and device approvals.</p>

            <a class="button" href="/admin">
                OPEN ADMIN PANEL
            </a>

        </div>
        """

    username = escape(current_user.username)

    content = f"""
    <h1>Dashboard</h1>

    <p>Welcome back, {username}.</p>

    <div class="grid">

        <div class="card">

            <h3>Available Balance</h3>

            <div class="balance">
                Rs. {current_user.balance:.2f}
            </div>

            <p class="small">
                Demo balance. Not withdrawable cash.
            </p>

        </div>

        <div class="card">

            <h3>Account Status</h3>

            <h2>ACTIVE</h2>

            <p>Your account is registered.</p>

        </div>

    </div>

    <div class="card">

        <h2>Watch Ads</h2>

        <p>
            Rewarded advertising will be available
            after an approved ad provider is connected.
        </p>

        <button disabled>
            WATCH AD - COMING SOON
        </button>

    </div>

    <div class="grid">

        <div class="card">

            <h3>My Profile</h3>

            <p>View your account information.</p>

            <a class="button" href="/profile">
                OPEN PROFILE
            </a>

        </div>

        <div class="card">

            <h3>Activity</h3>

            <p>See your recent account activity.</p>

            <a class="button" href="/activity">
                VIEW ACTIVITY
            </a>

        </div>

    </div>

    {admin_link}
    """

    return render_page(content, "Dashboard")


# ==========================================
# PROFILE
# ==========================================

@app.route("/profile")
@login_required
def profile():

    username = escape(current_user.username)
    email = escape(current_user.email)

    content = f"""
    <h1>My Profile</h1>

    <div class="card">
        <h3>Username</h3>
        <p>{username}</p>
    </div>

    <div class="card">
        <h3>Email</h3>
        <p>{email}</p>
    </div>

    <div class="card">
        <h3>Balance</h3>
        <div class="balance">
            Rs. {current_user.balance:.2f}
        </div>
    </div>

    <div class="card">
        <h3>Account Created</h3>
        <p>
            {current_user.created_at.strftime("%d %B %Y")}
        </p>
    </div>
    """

    return render_page(content, "Profile")


# ==========================================
# ACTIVITY HISTORY
# ==========================================

@app.route("/activity")
@login_required
def activity():

    records = Activity.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Activity.id.desc()
    ).limit(30).all()

    content = "<h1>Activity History</h1>"

    if not records:

        content += """
        <div class="card">
            <p>No activity found.</p>
        </div>
        """

    for record in records:

        action = escape(record.action)

        content += f"""
        <div class="card">

            <h3>{action}</h3>

            <p class="small">
                {record.created_at.strftime("%d %B %Y %H:%M")}
            </p>

        </div>
        """

    return render_page(content, "Activity")


# ==========================================
# ADMIN PANEL
# ==========================================

@app.route("/admin")
@admin_required
def admin():

    users = User.query.order_by(
        User.id.desc()
    ).all()

    total_users = User.query.count()

    content = f"""
    <h1>Admin Panel</h1>

    <div class="card">

        <h3>Total Registered Users</h3>

        <div class="balance">
            {total_users}
        </div>

    </div>

    <h2>User Management</h2>
    """

    for user in users:

        device_count = User.query.filter_by(
            device_hash=user.device_hash
        ).count()

        device = Device.query.filter_by(
            device_hash=user.device_hash
        ).first()

        extra_slots = device.extra_slots if device else 0

        username = escape(user.username)
        email = escape(user.email)

        content += f"""

        <div class="card">

            <h3>{username}</h3>

            <p>Email: {email}</p>

            <p>Device accounts: {device_count}</p>

            <p>Extra approved slots: {extra_slots}</p>

            <p>Admin: {"Yes" if user.is_admin else "No"}</p>

            <form method="POST"
            action="/admin/approve/{user.id}">

                <input type="hidden"
                name="csrf_token"
                value="__CSRF_TOKEN__">

                <input
                    type="number"
                    name="slots"
                    min="1"
                    max="10"
                    placeholder="Extra accounts to approve"
                    required
                >

                <button type="submit">
                    APPROVE EXTRA ACCOUNTS
                </button>

            </form>

        </div>
        """

    return render_page(content, "Admin")


# ==========================================
# ADMIN APPROVAL
# ==========================================

@app.route(
    "/admin/approve/<int:user_id>",
    methods=["POST"]
)
@admin_required
def approve(user_id):

    user = db.session.get(User, user_id)

    if not user:
        flash("User not found.")
        return redirect(url_for("admin"))

    try:
        slots = int(request.form.get("slots", 0))
    except ValueError:
        flash("Invalid number.")
        return redirect(url_for("admin"))

    if slots < 1 or slots > 10:
        flash("Enter a number between 1 and 10.")
        return redirect(url_for("admin"))

    device = Device.query.filter_by(
        device_hash=user.device_hash
    ).first()

    if not device:

        device = Device(
            device_hash=user.device_hash,
            extra_slots=0
        )

        db.session.add(device)

    device.extra_slots += slots

    db.session.commit()

    log_activity(
        current_user.id,
        f"Approved {slots} extra account slots for device"
    )

    flash("Extra account permission approved.")

    return redirect(url_for("admin"))


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
@login_required
def logout():

    user_id = current_user.id

    log_activity(
        user_id,
        "Logged out"
    )

    logout_user()

    flash("You have successfully logged out.")

    return redirect(url_for("home"))


# ==========================================
# ERROR PAGES
# ==========================================

@app.errorhandler(404)
def not_found(error):

    return render_page(
        """
        <div class="box">

            <h1>404</h1>

            <h2>Page Not Found</h2>

            <a class="button" href="/">
                GO HOME
            </a>

        </div>
        """,
        "404"
    ), 404


@app.errorhandler(500)
def server_error(error):

    db.session.rollback()

    return render_page(
        """
        <div class="box">

            <h1>500</h1>

            <h2>Something went wrong.</h2>

            <a class="button" href="/">
                GO HOME
            </a>

        </div>
        """,
        "Server Error"
    ), 500


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

with app.app_context():
    db.create_all()


# ==========================================
# RUN
# ==========================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
