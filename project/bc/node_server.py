#Originally from:
#https://github.com/satwikkansal/python_blockchain_app/tree/ibm_blockchain_post
import json
import time
from flask import Flask, request
import requests
from bc import app

from .blockchain import Blockchain, Block
#Temp imports

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import uuid
import unicodedata


# the node's copy of blockchain
blockchain = Blockchain()
blockchain.create_genesis_block()

# the address to other participating members of the network
peers = set()


@app.route('/', methods=['GET'])
def test():
    return 'BC Running'

# endpoint to submit a new certificate, not used currently
@app.route('/new_certificate', methods=['POST'])
def new_certificate():
    tx_data = request.get_json()
    #Old Implementation with firewall rules
    #required_fields = ["nw_src", "nw_dst", "nw_proto", "actions"]
    required_fields = ["role", "host", "ip", "mac"]

    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid certificate data", 404

    blockchain.add_new_certificate(tx_data)

    return "Success", 201


# endpoint to return the node's copy of the chain.
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})


# endpoint to request the node to mine the unconfirmed certificates (if any).
@app.route('/mine', methods=['GET'])
def mine_unconfirmed_certificates():
    result = blockchain.mine()
    if not result:
        return "No certificates to mine"
    else:
        # Making sure we have the longest chain before announcing to the network
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            # announce the recently mined block to the network
            announce_new_block(blockchain.last_block)
        return "Block #{} is mined.".format(blockchain.last_block.index)

@app.route('/create_cert', methods=['POST'])
def create_cert():
    # Load JSON from request
    req = request.get_json()

    # Old method of loading csr
    #pem_csr = json.loads((pem_csr["csr"])).encode('utf8', 'ignore') #possibly 'ascii'
    pem_csr = req["csr"].encode('utf8', 'ignore') #possibly 'ascii'
    csr = x509.load_pem_x509_csr(pem_csr, default_backend())

    # Load root cert and key
    pem_cert = open('bc/keys/cert.pem', 'rb').read()
    ca = x509.load_pem_x509_certificate(pem_cert, default_backend())
    pem_key = open('bc/keys/key.pem', 'rb').read()
    ca_key = serialization.load_pem_private_key(pem_key, password=None,
        backend=default_backend())

    # Create new certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca.subject)
    builder = builder.not_valid_before(datetime.datetime.now())
    builder = builder.not_valid_after(datetime.datetime.now() +
        datetime.timedelta(7)) # 7 days
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(int(uuid.uuid4()))
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, ext.critical)

    certificate = builder.sign(
        private_key = ca_key,
        algorithm = hashes.SHA256(),
        backend = default_backend()
    )

    # return or send certificate
    with open('bc/keys/test.crt', 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    cert = certificate.public_bytes(serialization.Encoding.PEM)
    new_cert = {
        "cert": cert,
        "ip": req["ip"]
    }
    blockchain.add_new_certificate(new_cert)
    blockchain.mine()

    return json.dumps(certificate.public_bytes(serialization.Encoding.PEM))

@app.route('/get_cert', methods=['GET'])
def get_cert():
    return open("bc/keys/test.crt", "rb").read()


# not sure how useful this code will be for current project plan
# endpoint to add new peers to the network.
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    # Add the node to the peer list
    peers.add(node_address)

    # Return the consensus blockchain to the newly registered node
    # so that he can sync
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    Internally calls the `register_node` endpoint to
    register current node with the node specified in the
    request, and sync the blockchain as well as peer data.
    """
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "Invalid data", 400

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    # Make a request to register with remote node and obtain information
    response = requests.post(node_address + "/register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # update chain and the peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        return "Registration successful", 200
    else:
        # if something goes wrong, pass it on to the API response
        return response.content, response.status_code


def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    generated_blockchain.create_genesis_block()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  # skip genesis block
        block = Block(block_data["index"],
                      block_data["certificates"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered!!")
    return generated_blockchain


# endpoint to add a block mined by someone else to
# the node's chain. The block is first verified by the node
# and then added to the chain.
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["certificates"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "The block was discarded by the node", 400

    return "Block added to the chain", 201


# endpoint to query unconfirmed certificates
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_certificates)


def consensus():
    """
    Our naive consnsus algorithm. If a longer valid chain is
    found, our chain is replaced with it.
    """
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block):
    """
    A function to announce to the network once a block has been mined.
    Other blocks can simply verify the proof of work and add it to their
    respective chains.
    """
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)
