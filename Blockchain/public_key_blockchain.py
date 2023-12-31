import hashlib
import json
from time import time
from urllib.parse import urlparse
import requests
from random import choice
from string import ascii_lowercase
import socket

class pKeyChain:
    def __init__(self):
        control = "ADMIN"
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        timestamp = str(time())
        p_key = control+ip_address+timestamp
        hash_key = hashlib.md5(p_key.encode())
        hexKey = hash_key.hexdigest()

        self.current_transactions = [{
            "public_key":hexKey
        }]
        self.chain = []
        self.nodes = set()
        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)


    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, key):
        self.current_transactions.append({
            'public_key': key,
        })

        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
    
    def validateKey(self,key):
        validVoteFlag = False
        try:
            for block in self.chain:   
                for transaction in block['transactions']:
                    if key == transaction['public_key']:
                        validVoteFlag = True
            return validVoteFlag
        except:
            return False
        
    def validateAdmin(self,key):
        validVoteFlag = True
        for block in self.chain:
            for transaction in block["transactions"]:
                try:
                    if transaction["public_key"] == key:
                            return True
                except:
                    return False
        return False


