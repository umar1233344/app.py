import os
import secrets
import hashlib

from flask import Flask, request, redirect, url_for, render_template_string, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", secrets.token_hex(32)
)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///adnova.db"
).replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"


# DATABASE MODELS

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    device_hash = db.Column(db.String(64), nullable=False)
    balance = db.Column(db.Float, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    extra_slots = db.Column(db.Integer, default=0)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def hash_device(token):
    return hashlib.sha256(token.encode()).hexdigest()


# SIMPLE PAGE DESIGN

PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADNOVA</title>
<style>
body {
    margin:0;
    background:#090d1c;
    color:white;
    font-family:Arial;
}
.box {
    max-width:430px;
    margin:70px auto;
    padding:25px;
    background:#151d35;
    border-radius:18px;
    box-shadow:0 0 25px #111c40;
}
h1 {color:#65e6ff;text-align:center}
input,button {
    width:100%;
    padding:13px;
    margin:9px 0;
    box-sizing:border-box;
    border:0;
    border-radius:9px;
}
button {
    background:#5b8cff;
    color:white;
    font-weight:bold;
}
a {color:#65e6ff}
.card {
    background:#202c4c;
    padding:15px;
    margin:12px 0;
    border-radius:12px;
}
</style>
</head>
<body>
<div class="box">
{{ content|safe }}
</div>
</body>
</html>
"""


def page(content):
    return render_template_string(PAGE, content=content)


# DEVICE ENROLLMENT

def get_device_token():
    token = request.cookies.get("adnova_device")

    if not token:
        token = secrets.token_urlsafe(32)

    return token


# HOME

@app.route("/")
def home():
    return page("""
    <h1>ADNOVA</h1>
    <p style="text-align:center">Watch Ads. Earn Rewards.</p>
    <a href="/register">Create Account</a><br><br>
    <a href="/login">Login</a>
    """)


# REGISTER

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if len(password) < 8:
            return page("Password must be at least 8 characters.")

        if User.query.filter_by(email=email).first():
            return page("Email already registered.")

        if User.query.filter_by(username=username).first():
            return page("Username already taken.")

        token = get_device_token()
        device = hash_device(token)

        existing = User.query.filter_by(device_hash=device).count()

        admin_email = os.environ.get("ADMIN_EMAIL", "").lower()
        is_admin = bool(admin_email and email == admin_email)

        # Default limit: 2 accounts per enrolled browser/device.
        permitted = 2

        if existing >= permitted:
            return page(
                "Account limit reached. Please contact the administrator."
            )

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            device_hash=device,
            is_admin=is_admin
        )

        db.session.add(user)
        db.session.commit()

        login_user(user)

        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie(
            "adnova_device",
            token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        return response

    return page("""
    <h1>Create Account</h1>
    <form method="POST">
        <input name="username" placeholder="Username" required>
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password"
               placeholder="Password (8+ characters)" required>
        <button>Register</button>
    </form>
    <a href="/login">Already have an account? Login</a>
    """)


# LOGIN

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        return page("Invalid email or password.")

    return page("""
    <h1>Login</h1>
    <form method="POST">
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Password" required>
        <button>Login</button>
    </form>
    <a href="/register">Create account</a>
    """)


# DASHBOARD

@app.route("/dashboard")
@login_required
def dashboard():

    return page(f"""
    <h1>ADNOVA</h1>
    <h2>Welcome, {current_user.username}</h2>

    <div class="card">
        <h3>Your Balance</h3>
        <h2>Rs. {current_user.balance:.2f}</h2>
    </div>

    <div class="card">
        <h3>Watch Ads</h3>
        <p>Ad provider integration is required.</p>
        <button disabled>Watch Ad - Coming Soon</button>
    </div>

    <div class="card">
        <a href="/profile">My Profile</a>
    </div>

    {"<a href='/admin'>Admin Panel</a><br><br>" if current_user.is_admin else ""}

    <a href="/logout">Logout</a>
    """)


# PROFILE

@app.route("/profile")
@login_required
def profile():
    return page(f"""
    <h1>My Profile</h1>
    <p>Username: {current_user.username}</p>
    <p>Email: {current_user.email}</p>
    <p>Balance: Rs. {current_user.balance:.2f}</p>
    <a href="/dashboard">Dashboard</a>
    """)


# ADMIN PANEL

@app.route("/admin")
@login_required
def admin():

    if not current_user.is_admin:
        return page("Access denied.")

    users = User.query.order_by(User.id.desc()).all()

    user_list = ""

    for user in users:
        user_list += f"""
        <div class="card">
            <b>{user.username}</b><br>
            {user.email}<br>
            Device accounts: {
                User.query.filter_by(device_hash=user.device_hash).count()
            }<br>
            Extra slots: {user.extra_slots}
            <form method="POST" action="/admin/approve/{user.id}">
                <input type="number" name="slots"
                       min="1" max="10" placeholder="Extra slots" required>
                <button>Approve Extra Accounts</button>
            </form>
        </div>
        """

    return page("<h1>Admin Panel</h1>" + user_list)


# ADMIN APPROVAL

@app.route("/admin/approve/<int:user_id>", methods=["POST"])
@login_required
def approve(user_id):

    if not current_user.is_admin:
        return page("Access denied.")

    user = db.session.get(User, user_id)

    if not user:
        return page("User not found.")

    slots = int(request.form["slots"])

    if slots < 1 or slots > 10:
        return page("Invalid number of slots.")

    user.extra_slots += slots
    db.session.commit()

    return redirect(url_for("admin"))


# LOGOUT

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


# DATABASE START

with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
