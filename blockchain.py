##################################################################################################
#                       BIBLIOTECAS NECESSÁRIAS
##################################################################################################

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from uuid import uuid4
import hashlib
from time import time
from Blockchain.vote_blockchain import voteChain,encrypt_vote
from Blockchain.public_key_blockchain import pKeyChain
import socket
from cryptography.fernet import Fernet

##################################################################################################
#                       DECLARAÇÃO & INICIALIZAÇÃO DE VARIÁVEIS
##################################################################################################

app = Flask(__name__)
CORS(app)

node_identifier = str(uuid4()).replace('-', '')

blockchain = voteChain()
keyChain = pKeyChain()
key = Fernet.generate_key()


##################################################################################################
#                       ROTAS DESTINADAS À VOTAÇÃO
##################################################################################################


#################################################################################################
#                       RENDERER
#################################################################################################

@app.route('/')
def renderIndex():
    return render_template('index.html')


##################################################################################################
#                       REALIZAR VOTAÇÃO
##################################################################################################

@app.route('/chain/add', methods=['POST'])
def voteMine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)
    data = request.json

    vote = str(data.get("vote"))
    public_key = str(data.get("p_key")) 

    # Método para verificar a validade da chave publica (se é válida & não foi utilizada) 
    if keyChain.validateKey(public_key) and blockchain.validateKey(public_key) :
        encrypted_vote = encrypt_vote(vote,key)
        blockchain.new_transaction(
            vote=encrypted_vote,
            p_key=public_key,
        )

        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, previous_hash)

        response = {
            'message': "New Block Forged",
            'index': block['index'],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        return jsonify(response), 200
    
    else:
        return jsonify({'error': 'Key is not valid'}), 500


##################################################################################################
#                      VERIFICAR NUMERO DE VOTOS
##################################################################################################

@app.route('/chain/length', methods=['GET'])
def voteLength():
    response = {
        'length': len(blockchain.chain)-1,
    }
    return jsonify(response), 200

##################################################################################################
#                       VERIFICAR RESULTADOS
##################################################################################################

@app.route('/chain/results', methods=['GET'])
def voteCount():
    try:
        response = {
            'votes': blockchain.get_all_votes(key)
        }
        return jsonify(response), 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

##################################################################################################
#                       VERIFICAR VENCEDOR
##################################################################################################

@app.route('/chain/mostVoted', methods=['GET'])
def mostVoted():
    try:
        response = {
            'Most_voted': blockchain.get_most_voted(key)
        }
        return jsonify(response), 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500

##################################################################################################
#                       CONSULTAR A BLOCKCHAIN
##################################################################################################


@app.route('/chain/display', methods=['GET'])
def voteDisplay():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'The chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'The chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

##################################################################################################
#                       ROTAS DESTINADAS À VOTAÇÃO
##################################################################################################

##################################################################################################
#                       GERAR CÓDIGO DE VOTAÇÃO
##################################################################################################

@app.route('/key/generate',methods=['POST'])
def keyMine():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    timestamp = str(time())
    p_key = ip_address+timestamp
    hash_key = hashlib.md5(p_key.encode())
    hexKey = hash_key.hexdigest()

    last_block = keyChain.last_block
    proof = keyChain.proof_of_work(last_block)
    keyChain.new_transaction(
        key=hexKey,
    )

    previous_hash = keyChain.hash(last_block)
    block = keyChain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

##################################################################################################
#                       CONSULTAR A BLOCKCHAIN
##################################################################################################

@app.route('/key/display', methods=['GET'])
def keyDisplay():
    replaced = keyChain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'The chain was replaced',
            'new_chain': keyChain.chain
        }
    else:
        response = {
            'message': 'The chain is authoritative',
            'chain': keyChain.chain
        }

    return jsonify(response), 200

##################################################################################################
#                       MAIN
##################################################################################################

if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port
    app.run(host='0.0.0.0', port=port)


