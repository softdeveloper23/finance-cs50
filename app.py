import os
import datetime


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
    # Get the user's id
    user_id = session["user_id"]

    # Get user's stocks and shares
    holdings = db.execute('SELECT stock_symbol, quantity FROM stocks WHERE user_id=?', (user_id,))

    # Get user's cash balance
    cash_balance = db.execute('SELECT cash FROM users WHERE id=?', (user_id,))[0]['cash']

    # Lookup the current price for each stock and calculate total value
    total_holdings_value = 0
    for holding in holdings:
        symbol = holding['stock_symbol']
        shares = holding['quantity']
        current_price = lookup(symbol)
        if current_price is None:
            # Handle the error, e.g., by showing an error message to the user
            return apology("Failed to fetch the current price for the stock", 400)
        price = current_price['price']
        total_value = shares * price
        holding['price'] = price
        holding['total_value'] = total_value
        holding['name'] = symbol
        total_holdings_value += total_value

    # Calculate grand total
    grand_total = float(total_holdings_value + cash_balance)
    total_holdings_value = float(total_holdings_value)
    cash_balance = float(cash_balance)

    # Render the index.html template, passing in the holdings, cash balance, and grand total
    return render_template('index.html', holdings=holdings, cash_balance=cash_balance, grand_total=grand_total, total_holdings_value=total_holdings_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')
        try:
            shares = int(shares)
        except ValueError:
            return apology("must provide whole number shares", 400)
        if not symbol:
            return apology("must provide symbol", 400)
        if not shares:
            return apology("must provide shares", 400)
        if shares < 0:
            return apology("must provide positive shares", 400)
        stock = lookup(symbol)
        if stock == None:
            return apology("Invalid symbol")
        else:
            # Get the user's id
            user_id = session["user_id"]

            # Get the user's cash balance
            cash_balance = db.execute('SELECT cash FROM users WHERE id=?', (user_id,))[0]['cash']
            cash_balance = float(cash_balance)

            # Get the stock's price at the time of purchase
            purchase_price = float(stock['price'])

            # Get the time of the stock purchase
            purchase_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Calculate the total cost of the purchase
            total_cost = float(stock['price'] * shares)

            # Check if the user has enough cash to make the purchase
            if total_cost > cash_balance:
                return apology("Insufficient funds")
            else:
                # Update the user's cash balance
                cash = cash_balance - total_cost

                db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, user_id)

                # Add the purchase to the 'stocks' database
                db.execute("INSERT INTO stocks (user_id, stock_symbol, purchase_price, purchase_date, quantity) VALUES (?, ?, ?, ?, ?)",
                    user_id, symbol, purchase_price, purchase_date, shares)
                return redirect('/')
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM stocks WHERE user_id = ?", user_id)
    return render_template('history.html', transactions=transactions)


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
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form['password']:
            return apology("must provide password", 400)

        # Ensure password was confirmed
        elif not request.form['confirmation']:
            return apology("must confirm password", 400)

        # Ensure password and confirmation match
        elif request.form['password'] != request.form['confirmation']:
            return apology("passwords do not match", 400)

        # Ensure username is not already taken
        elif len(db.execute("SELECT * FROM users WHERE username = ?", request.form['username'])) != 0:
            return apology("username is already taken", 400)

        # Ensure password is not already taken
        elif len(db.execute("SELECT * FROM users WHERE hash = ?", request.form['password'])) != 0:
            return apology("password is already taken", 400)

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
    holdings = db.execute('SELECT stock_symbol FROM stocks WHERE user_id=?', (session["user_id"],))
    symbols = [holding['stock_symbol'] for holding in holdings]
    if request.method == 'POST':
        if not request.form.get('symbol'):
            return apology("must provide symbol")
        elif not request.form.get('shares'):
            return apology("must provide shares")
        elif int(request.form.get('shares')) < 0:
            return apology("must provide positive shares")
        else:
            # Sell the shares
            symbol = request.form.get('symbol')
            shares_sold = int(request.form.get('shares'))
            stock = lookup(symbol)
            if stock == None:
                return apology("Invalid symbol")
            elif symbol not in symbols:
                return apology("You do not own any shares of this stock")
            else:
                # Get the user's id
                user_id = session["user_id"]

                # Get the user's cash balance
                cash_balance = db.execute('SELECT cash FROM users WHERE id=?', (user_id,))[0]['cash']
                cash_balance = float(cash_balance)

                # Get the stock's price at the time of purchase
                sell_price = float(stock['price'])

                # Get the time of the stock purchase
                sell_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Calculate the total cost of the purchase
                total_value = float(stock['price'] * shares_sold)

                # Check if the user has enough cash to make the purchase
                if total_value < 0:
                    return apology("Share worth must be positive")
                else:
                    # Fetch the current quantity of the stock
                    current_quantity = db.execute('SELECT quantity FROM stocks WHERE user_id=? AND stock_symbol=?', user_id, symbol)[0]['quantity']

                    # Check if the user is selling more shares than they own
                    if shares_sold > current_quantity:
                        return apology("You do not own that many shares of this stock")

                    # Update the user's cash balance
                    cash = cash_balance + total_value

                    db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, user_id)

                    # Update the user's stock quantity
                    quantity = current_quantity - shares_sold

                    # Get the purchase price of the stock
                    purchase_price = db.execute('SELECT purchase_price FROM stocks WHERE user_id=? AND stock_symbol=?', user_id, symbol)[0]['purchase_price']

                    # Get the purchase date of the stock
                    purchase_date = db.execute('SELECT purchase_date FROM stocks WHERE user_id=? AND stock_symbol=?', user_id, symbol)[0]['purchase_date']

                    # Add the sale to the 'stocks' database
                    db.execute("INSERT INTO stocks (user_id, stock_symbol, sell_price, sell_date, purchase_price, purchase_date, quantity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        user_id, symbol, sell_price, sell_date, purchase_price, purchase_date, quantity)
                    return redirect('/')
    else:
        return render_template('sell.html', holdings=holdings)

