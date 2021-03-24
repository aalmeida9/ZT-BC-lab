from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

import datetime
import uuid

from hashlib import sha256
import time


#block could hold the information of the mac address table or flow table
#mac address table contains the hosts connected to a switch and their ports
#flow table contains in-port: #, eth-dst: Host -> output: Port

#currently posts are stored in the BC and contain: Content, Author, timestamp
#Transcations are data, and a block can contain one to many transacations
class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        # Transcations contains relevant user attributes
        self.transactions = transactions
        # Consider using timestamp for certificate revocation
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.generate_keys()
        # Test for getter methods
        #print(self.get_public_key)
        #print(self.get_private_key)


    def compute_hash(self):
        """
        A function that return the hash of the block contents.
        """
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

    def generate_keys(self):
        # generate public and private key pair, from:
        # https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        # Set public key for each block as an attribute,
        # doesn't work due to json.dumps in compute_hash so just used get method

        # Store public and private keys for each block, to be accessed later
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('bc/keys/public_key_{}.pem'.format(self.index), 'wb') as f:
                f.write(pem)

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        # Consider using password protection:
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html#key-serialization
        # use index in filename
        with open('bc/keys/private_key_{}.pem'.format(self.index), 'wb') as f:
            f.write(pem)

    def get_public_key(self):
        """
        A function to retrieve the private key from a file.
        """
        with open("public_key_{}.pem".format(self.index), "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key

    def get_private_key(self):
        """
        A function to retrieve the private key from a file.
        """
        with open("private_key_{}.pem".format(self.index), "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        return private_key

class Blockchain:
    # difficulty of our PoW algorithm
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []
        self.chain = []

    def create_genesis_block(self):
        """
        A function to generate genesis block and appends it to
        the chain. The block has index 0, previous_hash as 0, and
        a valid hash.
        """

        genesis_block = Block(0, 0, 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        # Generate a root certificate for the blockchain
        self.add_cert(genesis_block)
        #append genesis block
        self.chain.append(genesis_block)

    def add_cert(self, block):
        """
        A function that adds a certificate to a block
        """
        # private_key = block.get_private_key
        # public_key = block.get_public_key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        builder = x509.CertificateBuilder()

        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'BC Test CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'BC'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Test')
        ]))

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'BC Test CA')
        ]))
        # Time validity
        builder = builder.not_valid_before(datetime.datetime.now())
        builder = builder.not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))

        builder = builder.serial_number(int(uuid.uuid4()))
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

        certificate = builder.sign(
            private_key = private_key,
            algorithm = hashes.SHA256(),
            backend=default_backend()
        )

        print(isinstance(certificate, x509.Certificate))


    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        """
        A function that adds the block to the chain after verification.
        Verification includes:
        * Checking if the proof is valid.
        * The previous_hash referred in the block and the hash of latest block
          in the chain match.
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    @staticmethod
    def proof_of_work(block):
        """
        Function that tries different values of nonce to get a hash
        that satisfies our difficulty criteria.
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        Check if block_hash is valid hash of block and satisfies
        the difficulty criteria.
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            # remove the hash field to recompute the hash again
            # using `compute_hash` method.
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):
        """
        This function serves as an interface to add the pending
        transactions to the blockchain by adding them to the block
        and figuring out Proof Of Work.
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True
