import sqlite3 as sql
import time
import random
import html 
import pyotp
import bcrypt
#     # ^(?=.*[a-z]) - At least one lowercase letter



def enable2FA(username, totp_code):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Retrieve the user's 2FA secret
    cur.execute("SELECT two_factor_secret FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    if not user:
        con.close()
        return False

    two_factor_secret = user[0]
    totp = pyotp.TOTP(two_factor_secret)

    # Verify the TOTP code
    if totp.verify(totp_code):
        # Mark 2FA as enabled in the database
        cur.execute("UPDATE users SET is_2fa_enabled = 1 WHERE username = ?", (username,))
        con.commit()
        con.close()
        return True

    con.close()
    return False

def insertUser(username, password, DoB, email):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Generate a 2FA secret
    two_factor_secret = pyotp.random_base32()

    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, email, two_factor_secret, is_2fa_enabled) VALUES (?, ?, ?, ?, ?, ?)",
        (username, hashed_password, DoB, email, two_factor_secret, 0),
    )
    con.commit()
    con.close()

def enable2FA(username, totp_code):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Retrieve the user's 2FA secret
    cur.execute("SELECT two_factor_secret FROM users WHERE username = ?", (username,))
    user = cur.fetchone()

    if not user:
        con.close()
        return False

    two_factor_secret = user[0]
    totp = pyotp.TOTP(two_factor_secret)

    # Verify the TOTP code
    if totp.verify(totp_code):
        # Mark 2FA as enabled in the database
        cur.execute("UPDATE users SET is_2fa_enabled = 1 WHERE username = ?", (username,))
        con.commit()
        con.close()
        return True

    con.close()
    return False

def retrieveUsers(username, password, email, totp_code):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()

    # Retrieve the user record
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND email = ?", (username, email)
    )
    user = cur.fetchone()

    if user:
        # Verify the hashed password
        stored_password = user[2]  # Assuming the password is in the second column
        two_factor_secret = user[4]  # Assuming the 2FA secret is in the fifth column
        if bcrypt.checkpw(password.encode('utf-8'), stored_password):
            # Verify the TOTP code
            totp = pyotp.TOTP(two_factor_secret)
            if totp.verify(totp_code):
                con.close()
                return True

    con.close()
    return False


def insertFeedback(feedback, username):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    sanitized_feedback = html.escape(feedback)  # Escape harmful content
    cur.execute("INSERT INTO feedback (feedback, username) VALUES (?, ?)", (sanitized_feedback, username))
    con.commit()
    con.close()

def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    feedback_list = []
    for row in data:
        escaped_feedback = html.escape(row[1])  # Escape feedback content
        feedback_list.append(escaped_feedback)
    return feedback_list

def isUserExists(username, email):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Check if the username or email exists
    cur.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username, email))
    user = cur.fetchone()
    con.close()
    return user is not None

