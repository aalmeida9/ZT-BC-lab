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

# "Demonstrator Page"
@app.route("/demo")
@app.route("/demo.html")
def demo():
    get_rules()
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

# "Topology Page"
@app.route("/topo")
@app.route("/topo.html")
def topo():
    network_topology = os.path.join(os.path.join('static'), 'topology.png')
    return render_template('topo.html', network_image = network_topology)


# 'Net Start'
@app.route("/netstart")
def netstart():
    command = 'sudo python net.py'
    os.system("gnome-terminal -e 'bash -c \""+command+";bash\"'")

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
        'mac': host["mac"]
    }

    #if user not in userList:
    userList.append(user)

    print(user)
    return redirect('/demo')

#route for adding rules from the form to the BC/Controller
@app.route("/add", methods=['POST'])
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

    #authenticate firewall rules for allowing traffic with hashes from BC
    if rule['actions'] == 'ALLOW':
        #returns a String
        ruleString = json.dumps(rule)
        #creates a hash
        ruleHash = sha256(ruleString.encode()).hexdigest()
        for hashes in hashList:
            if hashes == ruleHash:
                print("Hash matched: {}".format(hashes))
                print("Rule Authenticated: {}".format(rule))
                #add a redirect to double check a rule as is?
                if rule not in ruleList:
                    ruleList.append(rule)
                #break
    else:
        # Submit a transaction to the blockchain, only for DENY rules
        new_tx_address = "{}/new_transaction".format(BC_ADDRESS)
        mine_address = "{}/mine".format(BC_ADDRESS)

        requests.post(new_tx_address, json=rule,
        headers={'Content-type': 'application/json'})

    #add rule to rest_firewall (validate allow actions with BC) (test this)
    address = "{}/firewall/rules/0000000000000001".format(RYU_ADDRESS)
    # POST request commented out for testing
    #requests.post(address, json=rule,
    #headers={'Content-type': 'application/json'})

    return redirect('/')

# get firewall rules from BC
def get_rules():
    chain_address = ""
    response = ""
    try:
        chain_address = "{}/chain".format(BC_ADDRESS)
        response = requests.get(chain_address)

        #chain is a dict response.content is bytes
        chain = json.loads(response.content)
        for block in chain["chain"]:
            for rule in block["transactions"]:
                #inital logic for getting rule hashes on genesis block
                if block["index"] == 0:
                    hashList.append(rule)
                else:
                    if rule not in ruleList:
                        ruleList.append(rule)
    except requests.exceptions.RequestException as e:    # This is the correct syntax
        print(e)
        #print("Unable to access blockchain {}".format(response.status_code))

#still need to enable communication manually on Firewall:
#put http://localhost:8080/firewall/module/enable/0000000000000001

# Example method to configure  firewall with rules based on BC
# Add RequestExcept like above
def post_rules():
    address = "{}/firewall/rules/0000000000000001".format(RYU_ADDRESS)
    rule = {"nw_src": "10.0.0.1/32", "nw_dst": "10.0.0.2/32", "nw_proto": "ICMP"}
    r = requests.post(address, data=rule)
