import os, signal

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

# 'Kill'
@app.route("/killT")
def killT():
    name = 'runBC.py'
    try:

        # iterating through each instance of the proess
        for line in os.popen("ps ax | grep " + name + " | grep -v grep"):
            fields = line.split()

            # extracting Process ID from the output
            pid = fields[0]

            # terminating process
            os.kill(int(pid), signal.SIGKILL)
    except:
        print("Error Encountered while running script")

    return redirect('/startup')
