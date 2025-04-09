from flask import Flask, render_template, request, redirect, session, url_for
from flask_wtf.csrf import CSRFProtect
import user_management as dbHandler
from urllib.parse import urlparse, urljoin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import sqlite3 as sql
import os
import pyotp
import qrcode
from io import BytesIO
from flask import send_file
import base64

app = Flask(__name__)
app.secret_key = os.urandom(32)  # impossible to hack the secret_key 

# Whitelist of allowed URLs (relative paths)
ALLOWED_URLS = ["/", "/index.html", "/signup.html", "/success.html", "/logout"]

limiter = Limiter(
    get_remote_address,  # Use the client's IP address for rate-limiting
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Default limits for all routes
)

@app.route("/setup2fa/<username>", methods=["GET", "POST"])
def setup2fa(username):
    if request.method == "GET":
        con = sql.connect("database_files/database.db")
        cur = con.cursor()
        cur.execute("SELECT two_factor_secret FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        con.close()

        if not user:
            return "User not found", 404

        two_factor_secret = user[0]
        totp = pyotp.TOTP(two_factor_secret)
        uri = totp.provisioning_uri(username, issuer_name="SecurePWA")

        # Generate QR code
        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer)
        buffer.seek(0)

        # Encode the QR code as a base64 string
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        return render_template("setup2fa.html", qr_code=qr_code_base64, username=username)

    if request.method == "POST":
        totp_code = request.form["totp_code"]
        if dbHandler.enable2FA(username, totp_code):
            return redirect("/success.html")
        else:
            error_message = "Invalid 2FA code. Please try again."
            return render_template("setup2fa.html", error=error_message, username=username)


def is_safe_redirect_url(target):
    # Ensure the target URL is relative and in the whitelist
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.path in ALLOWED_URLS and ref_url.netloc == test_url.netloc

# Enable CSRF protection
csrf = CSRFProtect(app)

@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
@limiter.limit("5 per minute")  # Limit to 5 login attempts per minute
def home():
    if request.method == "GET":
        if "username" in session:
            return redirect("/success.html")
        return render_template("/index.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        # Check login credentials
        if dbHandler.isUserExists(username, email):
            session["username"] = username
            return redirect(url_for("verify2fa", username=username))
        else:
            error_message = "Invalid username or password."
            return render_template("/index.html", error=error_message)
        

@app.route("/verify2fa/<username>", methods=["GET", "POST"])
def verify2fa(username):
    if request.method == "GET":
        return render_template("verify2fa.html", username=username)
    if request.method == "POST":
        totp_code = request.form["totp_code"]
        if dbHandler.enable2FA(username, totp_code):
            session["username"] = username
            return redirect("/success.html")
        else:
            error_message = "Invalid 2FA code. Please try again."
            return render_template("verify2fa.html", error=error_message, username=username) 
               
@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET":
        return render_template("/signup.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        dob = request.form["dob"]
        email = request.form["email"]

        # Check if the username or email already exists
        if dbHandler.isUserExists(username, email):
            error_message = "Username or email already exists. Please try a different one."
            return render_template("/signup.html", error=error_message, username=username, email=email, dob=dob)

        # Validate username length
        if len(username) <= 6:
            error_message = "Invalid username. Username must be more than 6 characters."
            return render_template("/signup.html", error=error_message, username=username, email=email, dob=dob)

        # Validate password
        if not is_valid_password(password):
            error_message = "Invalid password. Password must be 12-32 characters long, contain at least 1 uppercase letter, 1 lowercase letter, and more than 4 numbers."
            return render_template("/signup.html", error=error_message, username=username, email=email, dob=dob)

        # Insert the user into the database
        dbHandler.insertUser(username, password, dob, email)
        return redirect(url_for("setup2fa", username=username))
    
@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if "username" not in session:
        return redirect("/")  # Redirect to login if not logged in

    if request.method == "POST":
        feedback = request.form["feedback"]
        # Validate feedback
        if len(feedback) > 500:
            return "Invalid feedback", 400
        dbHandler.insertFeedback(feedback, session["username"])

    feedback_list = dbHandler.listFeedback()  # Get the feedback data
    return render_template("/success.html", state=True, value=session["username"], feedback_list=feedback_list)
    
@app.route("/logout")
def logout():
    session.clear()  # Clear the session

    # Validate the next URL (if provided)
    next_url = request.args.get("next", "/")
    if not is_safe_redirect_url(next_url):
        next_url = "/"  # Default to a safe URL

    return redirect(next_url)
    
def is_valid_password(password):
    # Regex explanation:
    # ^(?=.*[a-z])       -> At least one lowercase letter
    # (?=.*[A-Z])        -> At least one uppercase letter
    # (?=.*\d.*\d.*\d.*\d) -> At least 4 numbers
    # [A-Za-z\d]{12,32}$ -> Length between 12 and 32 characters, only letters and numbers
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d.*\d.*\d.*\d)[A-Za-z\d]{12,32}$"
    return re.match(regex, password) is not None

@app.after_request
def add_header(response):
    # Disable caching
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response

@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many login attempts. Please try again later.", 429

if __name__ == "__main__":
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
