from flask import Flask, render_template, request, redirect, session
import user_management as dbHandler
import re

app = Flask(__name__)
app.secret_key = "your_secret_key"

@app.route("/index.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "GET":
        # Check if the user is already logged in
        if "username" in session:
            dbHandler.listFeedback()
            return render_template("/success.html", value=session["username"], state=True)
        return render_template("/index.html")
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]

        # Check login credentials
        isLoggedIn = dbHandler.retrieveUsers(username, password, email)
        if isLoggedIn:
            # Store user information in the session
            session["username"] = username
            session["email"] = email
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=True)
        else:
            # Generic error message for invalid login
            error_message = "Invalid username, password, or email. Please try again."
            return render_template("/index.html", error=error_message)

@app.route("/signup.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
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
        return render_template("/index.html")
    
@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if "username" not in session:
        return redirect("/")  # Redirect to login if not logged in

    if request.method == "POST":
        feedback = request.form["feedback"]
        # Validate feedback
        if len(feedback) > 500:
            return "Invalid feedback", 400
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        # Redirect to the feedback page after submission
        return redirect("/success.html")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value=session["username"])
    
@app.route("/logout")
def logout():
    session.clear()  # Clear the session
    return redirect("/")  # Redirect to the login page
    
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

@app.route("/2factorauthentificationgate.html")
def skibidi():
    return render_template("2factorauthentificationgate.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
