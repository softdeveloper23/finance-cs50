import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == 'POST':
        stock = {}
        # Get the stock symbol from the form
        symbol = request.form.get('symbol')
        if lookup(symbol) == None:
            return apology("Invalid symbol")
        else:
            stock = lookup(symbol)
            return render_template('quoted.html', stock=stock)
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':

        # Ensure username was submitted
        if not request.form['username']:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form['password']:
            return apology("must provide password", 403)

        # Ensure password was confirmed
        elif not request.form['confirmation']:
            return apology("must confirm password", 403)

        # Ensure password and confirmation match
        elif request.form['password'] != request.form['confirmation']:
            return apology("passwords do not match", 403)

        # Ensure username is not already taken
        elif len(db.execute("SELECT * FROM users WHERE username = ?", request.form['username'])) != 0:
            return apology("username is already taken", 403)

        # Ensure password is not already taken
        elif len(db.execute("SELECT * FROM users WHERE hash = ?", request.form['password'])) != 0:
            return apology("password is already taken", 403)

        # Get the username and password from the form

        username = request.form['username']
        plaintext_password = request.form['password']

        # Hash the password
        hashed_password = generate_password_hash(plaintext_password)

        # Insert the user into the database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

        # Redirect to the login page after registration
        return redirect('/login')
    else:
        # Render the registration template if method is GET
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")