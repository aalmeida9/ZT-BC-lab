from flask import render_template, redirect, request
from frontend import app

# Priority tasks:
# make a page to view topology,
# research flask resources that would demonstrate network/security capabilities
# create flags for if blockchain or ryu returns 404

# "Homepage"
@app.route("/")
@app.route("/index.html")
def index():
    return render_template('index.html')

# "About Page"
@app.route("/about")
@app.route("/about.html")
def about():
    return render_template('about.html')
