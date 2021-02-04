import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import Form, BooleanField, StringField, PasswordField, validators, SubmitField
import time
from helpers import apology, login_required, lookup, usd
import json
import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
#app.debug = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
timex = datetime.datetime.now()
# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    uidd =session["user_id"]
    sharesport = db.execute("SELECT * FROM sharescount WHERE uid=:uid AND totalshares >0", uid=uidd)

    stocksymbol= [d.get("symbol") for d in sharesport]

    stockinfo1 = [lookup(v) for v in stocksymbol]
    cashcheck2 = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session["user_id"])
    #cashcheck2 returns a list, we extract the number by the following loop
    cashcheck3 =list(map(lambda cashcheck3: cashcheck3["cash"], cashcheck2))
    for item in cashcheck3:
        cashcheck = float(item)

    return render_template("index.html", sharesport=sharesport, stockinfo1=stockinfo1, stocksymbol=stocksymbol,cashcheck=cashcheck,zip=zip)
    #return render_template("index.html")
    #return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock""" #DONE!! 10 HOURS
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("invalid stock symbol", 400)
        elif stock != None:

            amount = request.form.get("amount")
            shareprice= stock["price"]
            totalprice= shareprice * float(amount)
            #checking amount of cash avaliable
            cashcheck2 = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session["user_id"])
            #cashcheck2 returns a list, we extract the number by the following loop
            cashcheck3 =list(map(lambda cashcheck3: cashcheck3["cash"], cashcheck2))
            for item in cashcheck3:
                cashcheck = float(item)
            #checking cash status
            if totalprice > cashcheck:
                return apology("Insufficient funds")
            #buying stock
            else:
                stock = lookup(request.form.get("symbol"))
                newcash = '%.2f'% (cashcheck - totalprice) #updating cash"{:.0f}".format(float(Number)) '%.2f'%
                uidd =session["user_id"]
                db.execute("INSERT INTO recordsop ( uid, symbol, name, price, shares, totalpayment, operation, time) VALUES (:uid, :symbol, :name, :price , :shares, :totalpayment, :operation, :time )",
                uid = uidd, symbol = stock["symbol"], name = stock["name"], price = stock["price"], shares=amount, totalpayment = totalprice, operation="buy", time = timex )
                db.execute("UPDATE users SET cash = ? WHERE id = ?", ( newcash, uidd ) )
                #updating shares count per user
                newshare = db.execute("SELECT totalshares FROM sharescount WHERE (symbol = :symbol AND uid=:uid)", symbol= stock["symbol"], uid=uidd)
                if not newshare: #first time for this stock
                    db.execute("INSERT INTO sharescount (totalshares, symbol, uid) VALUES (:totalshares, :symbol,:uid) ",totalshares=amount, symbol = stock["symbol"], uid=uidd)
                elif newshare: #if share exists in portfolio the following excutes
                    newshare2 =list(map(lambda newshare2: newshare2["totalshares"], newshare)) #sql returns query to list - this function extract float
                    for sh in newshare2:
                        tshare = float(sh)
                        ttshare = tshare + float(amount)
                        db.execute("UPDATE sharescount SET (totalshares, symbol, uid) =(:totalshares,:symbol,:uid) WHERE (symbol=:symbol AND uid=:uid)", totalshares= ttshare, symbol = stock["symbol"], uid=uidd)
                else:
                    pass
                #testing for updating the avaliable cash after all is done
                # currentcash = db.execute("SELECT cash FROM users WHERE id = :userid", userid=uidd)
                # currentcash2 =list(map(lambda currentcash2: currentcash2["cash"], currentcash))
                # for item in currentcash2:
                #     avcash = float(item)

        return render_template("bought.html", stock=stock, amount=amount, newcash=float(newcash), totalprice=totalprice)

    else:
        return render_template("buy.html")

    #return apology("DONE")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    uidd =session["user_id"]
    historyrec = db.execute("SELECT * FROM recordsop WHERE  uid=:uid ORDER BY time DESC", uid=uidd)
    return render_template("history.html", historyrec=historyrec)

    #return apology("TODO")


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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

#validators.AnyOf(['!','@','#','$','%','^','&'])
#validators.AnyOf(['1','2','3','4','5','6','7','8','9','0']),
class changepasswordform(Form):
    password = PasswordField('Your Current Password', [validators.DataRequired()])
    newpassword = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirmnewpassword', message='Passwords have to match')
        ])
    confirmnewpassword = PasswordField('Confirm Your New Password')

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    uidd =session["user_id"]
    form = changepasswordform(request.form)
    if request.method == 'POST' and form.validate():
        rows = db.execute("SELECT hash FROM users WHERE id = :id",id=uidd)

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash('You entered wrong password, please try again')
            return render_template("changepassword.html")
        elif check_password_hash(rows[0]["hash"], request.form.get("password")) != check_password_hash(rows[0]["hash"], request.form.get("confirmnewpassword")):
            return render_template("changepassword.html")

        else:
            hash = generate_password_hash(request.form.get("newpassword"))
            db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash = hash, id=uidd)
            session.clear()
            flash('You successfully changed your password, please log in')
            return render_template('/login.html')
    else:

        return render_template("changepassword.html")
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
    """Get stock quote."""

    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))

        if stock == None:
            return apology("invalid stock symbol", 400)

        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirmation', message='Passwords have to match')
        ])
    confirmation = PasswordField('Repeat Password')

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user DONE"""

    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():

        newperson = db.execute("SELECT username FROM users WHERE username = :username", username=request.form.get("username"))
        if int(len(newperson)) > 0:
            return apology("username exist, please select another")

        else:
            hash = generate_password_hash(request.form.get("password"))
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username = request.form.get("username"), hash = hash)
        return redirect(url_for('login'))
    return render_template('register.html', form=form)



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    uidd =session["user_id"]
    if request.method == "GET":
        symbollist = db.execute("SELECT DISTINCT symbol FROM sharescount WHERE uid = :userid AND totalshares > 0", userid=uidd)
        return render_template("sell.html", symbollist=symbollist)
    elif request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        amount= request.form.get("amount")
        shareprice= stock["price"]
        totalsale= shareprice * float(amount)

        #checking number of shares the user owns
        sharecheck = db.execute("SELECT totalshares FROM sharescount WHERE (symbol = :symbol AND uid=:uid)", symbol= stock["symbol"], uid=uidd)
        if not sharecheck:
            return apology("You don't own any shares from this company")
        elif sharecheck:
            sharecheck2 = list(map(lambda sharecheck2: sharecheck2["totalshares"], sharecheck))
            for item in sharecheck2:
                sharesto= float(item)
                if sharesto < float(amount):
                    return apology("You don't own enugh shares from this company")
                else:
                                #checking amount of cash avaliable
                    cashcheck2 = db.execute("SELECT cash FROM users WHERE id = :userid", userid=session["user_id"])
                    #cashcheck2 returns a list, we extract the number by the following funcion
                    cashcheck3 =list(map(lambda cashcheck3: cashcheck3["cash"], cashcheck2))
                    for item in cashcheck3:
                        cashcheck = float(item)
                    newcash = '%.2f'%(cashcheck + totalsale)
                    sharestosell = -1.0 *float(amount)
                    ownedshares= sharesto - float(amount)
                    #update database with operation
                    db.execute("INSERT INTO recordsop ( uid, symbol, name, price, shares, totalpayment, operation, time) VALUES (:uid, :symbol, :name, :price , :shares , :totalpayment, :operation, :time  )",
                    uid = uidd, symbol = stock["symbol"], name = stock["name"], price = stock["price"], shares= sharestosell, totalpayment = totalsale, operation="sell", time = timex)
                    db.execute("UPDATE users SET cash = ? WHERE id = ?", ( newcash, uidd ) )
                    db.execute("UPDATE sharescount SET (totalshares, symbol, uid) =(:totalshares,:symbol,:uid) WHERE (symbol=:symbol AND uid=:uid)", totalshares= ownedshares, symbol = stock["symbol"], uid=uidd)
                    return render_template("sold.html", stock=stock, amount=amount, totalsale=totalsale, newcash=float(newcash))


    else:
        return apology("Oppsss! Something went wrong, sorry, please try again")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
