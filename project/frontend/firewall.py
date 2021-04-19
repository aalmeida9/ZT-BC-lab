import requests
import json

from flask import render_template, redirect, request
from frontend import app

RYU_ADDRESS = "http://0.0.0.0:8080"

#rules on the firewall
ruleList = []

# "Firewall Page"
@app.route("/firewall")
@app.route("/firewall.html")
def fw():
    return render_template('firewall.html', rules = ruleList)

@app.route("/startFW")
def startFW():
    try:
        address = "{}/firewall/module/enable/0000000000000001".format(RYU_ADDRESS)
        requests.put(address)
    except:
        print("Firewall App not running")
    return redirect('/firewall')

# Not used for demo
@app.route("/deleteRules")
def deleteRules():
    #still need to enable communication manually on Firewall:
    #put http://localhost:8080/firewall/module/enable/0000000000000001
    address = "{}/firewall/rules/0000000000000001".format(RYU_ADDRESS)
    delete = {"rule_id": "all"}
    requests.delete(address, json=delete,
    headers={'Content-type': 'application/json'})
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

    #add rule to Ryu rest_firewall
    address = "{}/firewall/rules/0000000000000001".format(RYU_ADDRESS)
    try:
        # Check for bidirectional rules
        if request.form["direction"] == "both":
            requests.post(address, json=rule,
            headers={'Content-type': 'application/json'})
            if rule not in ruleList:
                ruleList.append(rule)
            else:
                print("Rule already added")

            # Switch rule src/dst
            rule = {
                'nw_src': ip_dst,
                'nw_dst': ip_src,
                'nw_proto': proto_type,
                'actions': action
            }
            requests.post(address, json=rule,
            headers={'Content-type': 'application/json'})
        else:
            requests.post(address, json=rule,
            headers={'Content-type': 'application/json'})
    except:
        print("Firewall App not running")
    
    if rule not in ruleList:
        ruleList.append(rule)
    else:
        print("Rule already added")

    return redirect('/firewall')
