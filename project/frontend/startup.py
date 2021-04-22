import os, signal

from flask import render_template, redirect, request
from frontend import app

# "Startup Page"
@app.route("/startup")
@app.route("/startup.html")
def startup():
    topology1 = os.path.join(os.path.join('static'), 'topology1.png')
    topology2 = os.path.join(os.path.join('static'), 'topology2.png')
    return render_template('startup.html', net1 = topology1, net2 = topology2)

# 'Net Start'
@app.route("/netstart/<topo>")
def netstart(topo):
    command = 'sudo python net{}.py'.format(topo)
    if(topo == "2"):
        name = 'net1.py'
        try:

            # iterating through each instance of the proess
            for line in os.popen("ps ax | grep " + name + " | grep -v grep"):
                fields = line.split()

                # extracting Process ID from the output
                pid = fields[0]

                # terminating process
                os.kill(int(pid), signal.SIGKILL)
        except:
            print("Error encountered while terminating mininet script")
        try:
            os.system("gnome-terminal -- bash -c \""+command+"; bash\" &")
        except:
            print("Erorr encountered while executing mininet script")

    elif(topo == "1"):
        name = 'net2.py'
        try:

            # iterating through each instance of the proess
            for line in os.popen("ps ax | grep " + name + " | grep -v grep"):
                fields = line.split()

                # extracting Process ID from the output
                pid = fields[0]

                # terminating process
                os.kill(int(pid), signal.SIGKILL)
        except:
            print("Error encountered while terminating mininet script")
        try:
            os.system("gnome-terminal -- bash -c \""+command+"; bash\" &")
        except:
            print("Erorr encountered while executing mininet script")

    return redirect('/startup')

# 'Ryu Firewall Startup'
@app.route("/FWstart")
def FWstart():
    name = 'rest_sso.py'
    try:

        # iterating through each instance of the proess
        for line in os.popen("ps ax | grep " + name + " | grep -v grep"):
            fields = line.split()

            # extracting Process ID from the output
            pid = fields[0]

            # terminating process
            os.kill(int(pid), signal.SIGKILL)
    except:
        print("Error encountered while termininating SSO")

    try:
        ryuCommand = 'ryu-manager rest_firewall.py'
        os.system("gnome-terminal -- bash -c \""+ryuCommand+"; bash\" &")
    except:
        print("Error encountered while executing FW")

    return redirect('/startup')

# 'Ryu Single Sign-On Startup'
@app.route("/SSOstart")
def SSOstart():
    name = 'rest_firewall.py'
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

    try:
        ryuCommand = 'ryu-manager rest_sso.py'
        os.system("gnome-terminal -- bash -c \""+ryuCommand+"; bash\" &")
    except:
        print("Error encountered while executing SSO")
    #os.system("gnome-terminal -e 'bash -c \""+ryuCommand+";bash\"'")
    return redirect('/startup')

# 'BC Start'
@app.route("/bcstart")
def bcstart():
    try:
        bcCommand = 'sudo python runBC.py'
        os.system("gnome-terminal -- bash -c \""+bcCommand+"; bash\" &")
    except:
        print("Error encountered while executing BC")

    return redirect('/startup')
