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

# Create a dictionary for certificates {ip: cert}
certs = {}

# "Demonstrator Page"
@app.route("/sso")
@app.route("/sso.html")
def sso():
    # get_rules()
    return render_template('sso.html',
    hosts = hostList, users = userList, node_address=BC_ADDRESS)

# "Admin Page"
@app.route("/admin")
@app.route("/admin.html")
def admin():
    return render_template('admin.html',
    users = userList, node_address=BC_ADDRESS)

# Get IP from mininet hosts
@app.route("/getHost", methods=['POST'])
def getHost():
    # Need to process Dictionary, ip
    host = json.loads(request.json)
    print(host)

    if host not in hostList:
        hostList.append(host)

    return '0'

# Add user roles from the frontend
@app.route("/addUser", methods=['POST'])
def addUser():
    host = hostList[int(request.form["hostNum"])]

    user = {
        'role': int(request.form["dropdown"]),
        'host': host["host"],
        'ip': host["ip"],
        'mac': host["mac"],
        'in': ''
    }

    # check if host already configured in userList
    if user not in userList:
        userList.append(user)

    return redirect('/sso')

# Configures the SSO with rules configured based on each role then starts SSO
@app.route("/startSSO")
def startSSO():
    for user in userList:
        ip = user["ip"]
        role = {
            'nw_src': ip,
            'role': user["role"]
        }

        if ip in certs.keys():
            role["cert"] = certs[ip]
            print(role)
            #send role with cert, roles needs rule info from user

        role = json.dumps(role)

        address = "{}/SSO/roles/0000000000000001".format(RYU_ADDRESS)
        response = requests.post(address, json=role,
            headers={'Content-type': 'application/json'})

    address = "{}/SSO/module/enable/0000000000000001".format(RYU_ADDRESS)
    response = requests.put(address,
        headers={'Content-type': 'application/json'})

    return "Succes"

# Create certificate signing request that is sent to CA (blockchain)
@app.route("/buildCSR", methods=['POST'])
def csr():
    # Handle if user isn't selected

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Configure with input from form
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

    # consider link pem_req : public bytes and selected user : ip
    pem_req = req.public_bytes(Encoding.PEM)
    user = userList[int(request.form["userNum"])]
    ip = user["ip"]

    json_req = {
         "csr": pem_req,
         "ip": ip
     }

    address = "{}/create_cert".format(BC_ADDRESS)
    response = requests.post(address, json=json_req,
        headers={'Content-type': 'application/json'})

    cert = json.loads(response.text).encode('utf8')

    user = userList[int(request.form["userNum"])]
    if(user['role'] == 1):
        certs[ip] = cert

    # Probably load_pem after certs
    cert = x509.load_pem_x509_certificate(cert, default_backend())

    return redirect('/sso')

    # Send request to CA with REST
    # Move on to CA in node_server

    # with open('test.csr', 'wb') as f:
    #     f.write(request.public_bytes(Encoding.PEM))
    #
    # with open('test.key', 'wb') as f:
    #     f.write(private_key.private_bytes(Encoding.PEM,
    #         PrivateFormat.TraditionalOpenSSL, NoEncryption))
