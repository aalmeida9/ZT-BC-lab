import requests
import json
import os
from hashlib import sha256

from flask import Blueprint, render_template, redirect, request
from frontend import app

#Priority tasks:
#make a page to view topology
#research flask resources that would demonstrate network/security capabilities
#create flags for if blockchain or ryu returns 404

#address to the Flask blockchain
BC_ADDRESS = "http://127.0.0.1:8000"
#address to the ryu controller
RYU_ADDRESS = "http://0.0.0.0:8080"
#alternatives "http://127.0.0.1:8080" "http://localhost:8080"

#rules on the firewall
ruleList = []
#hashes of acceptable rules (from BC)
hashList = []

#host configurations received from the network
hostList = []
#users are hosts that have been configured with the Blockchain
#initally implement CA with just hashes then move onto public/private key
userList = []

#Rules are registered to the switch as flow entries, Rule format:
#{"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP"}
#make sure duplicate rules don't get added to firewall

# "Homepage"
@app.route("/")
@app.route("/index.html")
def index():
    return render_template('index.html')

# "Firewall Page"
@app.route("/firewall")
@app.route("/firewall.html")
def fw():
    return render_template('firewall.html',
    rules = ruleList)

# "Demonstrator Page"
@app.route("/demo")
@app.route("/demo.html")
def demo():
    # get_rules()
    return render_template('demo.html',
    hosts = hostList, users = userList)

# "Admin Page"
@app.route("/admin")
@app.route("/admin.html")
def admin():
    return render_template('admin.html',
    users = userList)

# "About Page"
@app.route("/about")
@app.route("/about.html")
def about():
    return render_template('about.html')

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

# Get IP from hosts, potentially add a GET method for sending IPs to Ryu or BC
@app.route("/getHost", methods=['POST'])
def getHost():
    # Need to process Dictionary, ip
    host = json.loads(request.json)
    print(host)

    if host not in hostList:
        hostList.append(host)

    return '0'


@app.route("/addUser", methods=['POST'])
def addUser():
    host = int(request.form["hostNum"])
    #print(type(hostList[host]))
    #print(type(hostList[host]))
    host = hostList[host]
    user = {
        'role': request.form["dropdown"],
        'host': host["host"],
        'ip': host["ip"],
        'mac': host["mac"],
        'in': ''
    }

    # Need to check if another host is in user list with different role
    # delete different role of same host
    if user not in userList:
        userList.append(user)

    print(user)
    return redirect('/demo')

@app.route("/startFW")
def startFW():
    #still need to enable communication manually on Firewall:
    #put http://localhost:8080/firewall/module/enable/0000000000000001
    return redirect('/firewall')

#route for adding rules from the form to the BC/Controller
@app.route("/addRule", methods=['POST'])
def add():
    #Load neccessary attributes for firewall rule from HTML form
    ip_src = request.form["src"]
    ip_dst = request.form["dst"]
    proto_type = request.form["dropdown"]
    action = request.form['actions']

    #add logic to make rules go both ways possibly an HTML button

    #create a dictionary to represent the firewall rule
    rule = {
        'nw_src': ip_src,
        'nw_dst': ip_dst,
        'nw_proto': proto_type,
        'actions': action
    }

    #add logic to stop duplicate rules
    ruleList.append(rule)

    #add rule to rest_firewall (validate allow actions with BC) (test this)
    address = "{}/firewall/rules/0000000000000001".format(RYU_ADDRESS)
    # POST request commented out for testing
    requests.post(address, json=rule,
    headers={'Content-type': 'application/json'})

    return redirect('/firewall')
