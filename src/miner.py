import time
import hashlib
import json
import requests
import base64
import os
from flask import Flask, request
from multiprocessing import Process, Pipe
import ecdsa

from miner_config import MINER_ADDRESS, MINER_NODE_URL, PEER_NODES

node = Flask(__name__)


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.hash_block()

    def merkle_hash(self):
        if not self.data:
            return ''
        if not self.data['transactions']:
            return ''
        transactions = self.data['transactions']
        sha = hashlib.sha256()

        hashing_tree = transactions[:]
        while len(hashing_tree) > 1:
            first = hashing_tree[0]
            second = hashing_tree[1]
            hashing_tree.pop(0)
            hashing_tree.pop(0)
            sha.update((str(first) + str(second)).encode('utf-8'))
            hashing_tree.append(sha.hexdigest)
        sha.update((str(self.data['proof-of-work']) + str(hashing_tree[0])).encode('utf-8'))
        return sha.hexdigest()
    
    def hash_block(self):
        sha = hashlib.sha256()
        sha.update((str(self.index) + str(self.timestamp) + str(self.merkle_hash())+ str(self.previous_hash)).encode('utf-8'))
        return sha.hexdigest()


def create_genesis_block():
    return Block(0, time.time(), {
        "proof-of-work": 9,
        "transactions": None},
        "0")


# Node's blockchain copy
BLOCKCHAIN = [create_genesis_block()]

NODE_PENDING_TRANSACTIONS = []

def json_to_blcokchain(json_blockchain):
    blockchain = []
    for block_json in json_blockchain:
        block = Block('', '', {'transactions': None}, '')
        block.index=int(block_json["index"])
        block.timestamp=block_json["timestamp"]
        block.data=json.loads(block_json["data"])
        block.hash=block_json["hash"]
        block.previous_hash=block_json["previous_hash"]
        
        blockchain.append(block)
    return blockchain
    

def blockchain_to_json(blockchain):
    chain_to_send_json = []
    for block in blockchain:
        block = {
            "index": int(str(block.index)),
            "timestamp": str(block.timestamp),
            "data": json.dumps(block.data),
            "hash": block.hash,
            "previous_hash": block.previous_hash
        }
        chain_to_send_json.append(block)
    return chain_to_send_json

def proof_of_work(last_proof, blockchain):
    incrementer = 0#last_proof + 1

    start_time = time.time()
    while not (incrementer == 10000000):# % 7919 == 0 and incrementer % last_proof == 0):
        incrementer += 1

        if int((time.time()-start_time) % 60) == 0:

            new_blockchain = consensus(blockchain)
            if new_blockchain:

                return False, new_blockchain

    return incrementer, blockchain

def save_blockchain(blockchain):
    blockchain_json = blockchain_to_json(blockchain)

    with open("miner_blockchain", 'w') as file:
        json.dump(blockchain_json, file, indent=4, sort_keys=True)

def mine(a, blockchain, node_pending_transactions):
    BLOCKCHAIN = blockchain
    NODE_PENDING_TRANSACTIONS = node_pending_transactions
    while True:
        last_block = BLOCKCHAIN[-1]
        last_proof = last_block.data['proof-of-work']

        proof = proof_of_work(last_proof, BLOCKCHAIN)

        if not proof[0]:

            BLOCKCHAIN = proof[1]
            a.send(BLOCKCHAIN)
            save_blockchain(BLOCKCHAIN)
            continue
        else:

            NODE_PENDING_TRANSACTIONS = requests.get(url = MINER_NODE_URL + '/txion', params = {'update':MINER_ADDRESS}).content
            NODE_PENDING_TRANSACTIONS = json.loads(NODE_PENDING_TRANSACTIONS)

            NODE_PENDING_TRANSACTIONS.append({
                "from": "network",
                "to": MINER_ADDRESS,
                "amount": 1})

            new_block_data = {
                "proof-of-work": proof[0],
                "transactions": list(NODE_PENDING_TRANSACTIONS)
            }
            new_block_index = last_block.index + 1
            new_block_timestamp = time.time()
            last_block_hash = last_block.hash

            NODE_PENDING_TRANSACTIONS = []

            mined_block = Block(new_block_index, new_block_timestamp, new_block_data, last_block_hash)
            BLOCKCHAIN.append(mined_block)
            validated = validate_blockchain(BLOCKCHAIN)
            if not validated:
                BLOCKCHAIN.pop()
                print("Failed to add block, invalid state")
                continue

            print(json.dumps({
              "index": new_block_index,
              "timestamp": str(new_block_timestamp),
              "data": new_block_data,
              "hash": last_block_hash
            }, sort_keys=True) + "\n")
            a.send(BLOCKCHAIN)
            save_blockchain(BLOCKCHAIN)
            requests.get(url = MINER_NODE_URL + '/blocks', params = {'update':MINER_ADDRESS})
            

def find_new_chains():
    other_chains = []
    for node_url in PEER_NODES:
        block = requests.get(url = node_url + "/blocks").content
        block = json.loads(block)
        validated = validate_blockchain(block)

        if validated:
            other_chains.append(block)
    return other_chains


def consensus(blockchain):
    other_chains = find_new_chains()
    BLOCKCHAIN = blockchain
    longest_chain = BLOCKCHAIN

    for chain in other_chains:
        if len(longest_chain) < len(chain):
            longest_chain = chain
            
    if longest_chain == BLOCKCHAIN:
        return False
    else:
        BLOCKCHAIN = longest_chain
        return BLOCKCHAIN

def generate_user_data(blockchain):
    data = {}
    for block in blockchain:
        if not block.data['transactions']:
            continue
        for transaction in block.data['transactions']:
            from_id = transaction['from']
            to_id = transaction['to']
            if not from_id in data:
                data[from_id] = {}
                data[from_id]['current'] = 0
                data[from_id]['min'] = 0
                data[from_id]['max'] = 0
            if not to_id in data:
                data[to_id] = {}
                data[to_id]['current'] = 0
                data[to_id]['min'] = 0
                data[to_id]['max'] = 0
            data[from_id]['current'] -= int(transaction['amount'])
            data[to_id]['current'] += int(transaction['amount'])
            data[from_id]['min'] = min(data[from_id]['min'], data[from_id]['current'])
            data[from_id]['max'] = max(data[from_id]['max'], data[from_id]['current'])
            data[to_id]['min'] = min(data[to_id]['min'], data[to_id]['current'])
            data[to_id]['max'] = max(data[to_id]['max'], data[to_id]['current'])
    return data


def validate_blockchain(block):
    data = generate_user_data(block)
    for name, user in data.items():
        if name == 'network':
            continue
        if user['current'] < 0 or user['min'] < 0:
            return False
    return True



@node.route('/users', methods=['GET'])
def get_users():
    user_data = generate_user_data(BLOCKCHAIN)
    json_data = json.dumps(user_data)
    return json_data


@node.route('/blocks', methods=['GET'])
def get_blocks():
    if request.args.get("update") == MINER_ADDRESS:
        global BLOCKCHAIN
        BLOCKCHAIN = pipe_input.recv()
    chain_to_send = BLOCKCHAIN

    chain_to_send_json = blockchain_to_json(chain_to_send)

    chain_to_send = json.dumps(chain_to_send_json, sort_keys=True)
    return chain_to_send


@node.route('/txion', methods=['GET', 'POST'])
def transaction():
    """Each transaction sent to this node gets validated and submitted.
    Then it waits to be added to the blockchain. Transactions only move
    coins, they don't create it.
    """
    if request.method == 'POST':

        new_txion = request.get_json()
        users_data = generate_user_data(BLOCKCHAIN)
        if not new_txion['from'] in users_data:
            return "Not found user"
        user_data = users_data[new_txion['from']]
        amount = new_txion['amount']
        valid_amount = user_data['current'] - amount >= 0
        if valid_amount and validate_signature(new_txion['from'], new_txion['signature'], new_txion['message']):
            NODE_PENDING_TRANSACTIONS.append(new_txion)

            print("New transaction")
            print("FROM: {0}".format(new_txion['from']))
            print("TO: {0}".format(new_txion['to']))
            print("AMOUNT: {0}\n".format(new_txion['amount']))

            return "Transaction submission successful\n"
        else:
            return "Transaction submission failed. Wrong signature\n"
    elif request.method == 'GET' and request.args.get("update") == MINER_ADDRESS:
        pending = json.dumps(NODE_PENDING_TRANSACTIONS, sort_keys=True)

        NODE_PENDING_TRANSACTIONS[:] = []
        return pending


def validate_signature(public_key, signature, message):
    """Verifies if the signature is correct. This is used to prove
    it's you (and not someone else) trying to do a transaction with your
    address. Called when a user tries to submit a new transaction.
    """
    public_key = (base64.b64decode(public_key)).hex()
    signature = base64.b64decode(signature)
    vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)

    try:
        return vk.verify(signature, message.encode())
    except:
        return False


def welcome_msg():
    print("""       =========================================\n
        SIMPLE COIN - BLOCKCHAIN SYSTEM\n
       =========================================\n\n\n""")

def load_blockchain():
    if not os.path.exists("miner_blockchain"):
        return
    with open("miner_blockchain", 'r') as file:
        global BLOCKCHAIN
        BLOCKCHAIN = json_to_blcokchain(json.load(file))


if __name__ == '__main__':
    welcome_msg()
    load_blockchain()
    pipe_output, pipe_input = Pipe()
    miner_process = Process(target=mine, args=(pipe_output, BLOCKCHAIN, NODE_PENDING_TRANSACTIONS))
    miner_process.start()

    transactions_process = Process(target=node.run(), args=pipe_input)
    transactions_process.start()
