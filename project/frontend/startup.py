import os

from flask import render_template, redirect, request
from frontend import app

# "Startup Page"
@app.route("/startup")
@app.route("/startup.html")
def startup():
    network_topology = os.path.join(os.path.join('static'), 'topology.png')
    return render_template('startup.html', network_image = network_topology)

# 'Net Start'
@app.route("/netstart/<topo>")
def netstart(topo):
    command = 'sudo python net{}.py'.format(topo)
    os.system("gnome-terminal -e 'bash -c \""+command+";bash\"'")
    return redirect('/startup')

# 'Ryu Start'
@app.route("/ryustart")
def ryustart():
    #cdCommand = 'cd ..'
    ryuCommand = 'ryu-manager ryu.app.rest_firewall'
    os.system("gnome-terminal -e 'bash -c \""+ryuCommand+";bash\"'")
    return redirect('/startup')

# 'BC Start'
@app.route("/bcstart")
def bcstart():
    #cdCommand = 'cd ..'
    bcCommand = 'sudo python runBC.py'
    os.system("gnome-terminal -e 'bash -c \""+bcCommand+";bash\"'")
    return redirect('/startup')
