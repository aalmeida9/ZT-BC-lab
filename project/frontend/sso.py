import requests
import json

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (Encoding,
    PrivateFormat, NoEncryption)

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
    users = userList, node_address=BC_ADDRESS)

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

    host = hostList[host]
    user = {
        'role': request.form["dropdown"],
        'host': host["host"],
        'ip': host["ip"],
        'mac': host["mac"],
        'in': ''
    }

    # check if host already configured in userList
    if user not in userList:
        userList.append(user)

    print(user)
    return redirect('/demo')

# Start of Certificates

@app.route("/buildCSR")
def csr():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    req = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'Server'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Test Server'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Massachusetts'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Dartmouth'),
    ])).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical = True,
    ).sign(private_key, hashes.SHA256(), default_backend())

    # This BasicConstraints won't allow this certificate to sign other certs
    # builder = builder.add_extension(
    #     x509.BasicConstraints(ca=False, path_length=None), critical = True,
    # )

    # request = builder.sign(
    #     private_key, hashes.SHA256(), default_backend()
    # )

    pem_key = private_key.private_bytes(Encoding.PEM,
    PrivateFormat.TraditionalOpenSSL, NoEncryption())
    pem_req = req.public_bytes(Encoding.PEM)

    #print("{}".format(pem_req.decode()))
    print(type(pem_req.decode()))
    print(type(pem_req))
    json_req = json.dumps(pem_req)
    json_key = json.dumps(pem_key)
    #print(test)

    return redirect('/')

    # Send request to CA with REST
    # Move on to CA in node_server

    # with open('test.csr', 'wb') as f:
    #     f.write(request.public_bytes(Encoding.PEM))
    #
    # with open('test.key', 'wb') as f:
    #     f.write(private_key.private_bytes(Encoding.PEM,
    #         PrivateFormat.TraditionalOpenSSL, NoEncryption))
