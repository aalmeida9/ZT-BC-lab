from flask import render_template, redirect, request
from frontend import app

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
