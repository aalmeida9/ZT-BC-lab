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

            os.system("gnome-terminal -e 'bash -c \""+command+";bash\"'")
        except:
            print("Error Encountered while running script")
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

            os.system("gnome-terminal -e 'bash -c \""+command+";bash\"'")
        except:
            print("Error Encountered while running script")

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
        print("Error Encountered while running script")
    #cdCommand = 'cd ..'
    ryuCommand = 'ryu-manager firewall.py'
    os.system("gnome-terminal -e 'bash -c \""+ryuCommand+";bash\"'")
    return redirect('/startup')

# 'Ryu Single Sign-On Startup'
@app.route("/SSOstart")
def SSOstart():
    name = 'firewall.py'
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
    #cdCommand = 'cd ..'
    ryuCommand = 'ryu-manager rest_sso.py'
    os.system("gnome-terminal -e 'bash -c \""+ryuCommand+";bash\"'")
    return redirect('/startup')

# 'BC Start'
@app.route("/bcstart")
def bcstart():
    #cdCommand = 'cd ..'
    bcCommand = 'sudo python runBC.py'
    os.system("gnome-terminal -e 'bash -c \""+bcCommand+";bash\"'")
    return redirect('/startup')

# 'Kill RYU'
@app.route("/killRyu")
def killRyu():
    name = 'firewall.py'
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

    # 'Kill Mini'
@app.route("/killMini")
def killMini():
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
        print("Error Encountered while running script")

    return redirect('/startup')
