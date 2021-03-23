import requests
import json

from flask import render_template, redirect, request
from frontend import app

#address to the Flask blockchain
BC_ADDRESS = "http://127.0.0.1:8000"
#address to the ryu controller
RYU_ADDRESS = "http://0.0.0.0:8080"
#alternatives "http://127.0.0.1:8080" "http://localhost:8080"

#host configurations received from the network
hostList = []
#users are hosts that have been configured with the Blockchain
#initally implement CA with just hashes then move onto public/private key
userList = []

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
