import os
import hmac
import hashlib
import binascii
import json
import logging

from flask import Flask
from flask import request
from flask import Response

from web3 import Web3
from eth_account import Account, messages

from eip712_structs import make_domain
from eip712_structs import EIP712Struct, Uint, Address, Bytes, make_domain

from dotenv import load_dotenv

load_dotenv('.env')

gtc_sig_app = Flask(__name__)
logging.basicConfig(filename='request-signer.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

# load our envars 
gtc_sig_app.config.from_pyfile('setup.py')

# load the distribution proofs
try:
    with open('dist_proofs.json') as data:
        gtc_sig_app.logger.info('Successfully loaded distribution proofs.')
        proofs = json.load(data)
except:
    msg = "There was an issue opening distribution proof file."
    gtc_sig_app.logger.error(msg)
    raise RuntimeError(msg)

gtc_sig_app.logger.info(gtc_sig_app.config.get("GTC_SIG_KEY"))

@gtc_sig_app.route('/')
def hello_world():
    return 'WELCOME!'

@gtc_sig_app.route('/v1/sign_claim', methods=['POST'])
def sign_claim():
    '''
    Provided payload of datas including, HMAC signed headers, will return EIP712 compliant 
    struct that a user can use to claim tokens by sending to the a TokenDistributor contract
    '''
    # IP based restrictions will probably be done at the firewall level
    ip_address = request.remote_addr
    gtc_sig_app.logger.info(f'Request IP: {ip_address}')

    # extract our headers, log headers for debugging
    headers = request.headers
    gtc_sig_app.logger.debug(f'Incoming POST request headers:{request.headers}')

    # extract POST data as json, log POST data for debugging
    json_request = request.get_json()
    gtc_sig_app.logger.debug(f'POST BODY DATA:{json_request}')

    # calc HMAC hash for our POST data, log computed hash for debugging
    computed_hash = create_sha256_signature(gtc_sig_app.config.get("GTC_SIG_KEY"), json.dumps(json_request))
    gtc_sig_app.logger.debug(f'COMPUTED HASH: {computed_hash}')

    # confirm we have POST data
    try:
        user_id = json_request['user_id']
        user_address = json_request['user_address']
        user_amount = json_request['user_amount']
        delegate_address =  json_request['delegate_address']
    except TypeError:
        gtc_sig_app.logger.info('Generic POST data TypeError received - confirm required values have been provided in POST payload')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json')
    except Exception as e:
        gtc_sig_app.logger.error(f'GTC Claim Generator error: {e}')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json') 

    # validate post body data 
    if not Web3.isAddress(user_address):
        gtc_sig_app.logger.error('Invalid user_address received!')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json')
    if not Web3.isAddress(delegate_address):
        gtc_sig_app.logger.error('Invalid delegate_address received!')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json')
    
    # make sure user_id is an integer 
    try:
        user_id = int(user_id)
    except ValueError:
        gtc_sig_app.logger.error('Invalid user_id received!')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json')
    
    # make sure it's an int
    try: 
        user_amount = int(user_amount)
    except ValueError:
        gtc_sig_app.logger.error('Invalid user_amount received!')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json') 
    
    # get leaf and proofs for user
    try:
        leaf = proofs[str(user_id)]['leaf']
        proof = proofs[str(user_id)]['proof']
        leaf_bytes = Web3.toBytes(hexstr=leaf)
    except Exception as e:
        gtc_sig_app.logger.error(f'There was an error getting user claim proof: {e}')
        return Response('{"message":"ESMS error"}', status=400, mimetype='application/json')
    
    # check if the hashes match for HMAC sig, if so, we can proceed to created eth signed message  
    if headers['X-GITCOIN-SIG'] == computed_hash:
        # build out EIP712 struct 
        signable_message = createSignableStruct(user_id, user_address, user_amount, delegate_address, leaf_bytes) 
        # sign it up
        try:
            eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign(signable_message)
        except Exception as e:
            gtc_sig_app.logger.error(f'GTC Distributor - Error Hashing Message: {e}')
            return Response('{"message":"ESMS error"}', status=500, mimetype='application/json')

        # this is a bit of hack to avoid bug in old web3 on frontend
        # this means that user_amount is not converted back to wei before tx is broadcast! 
        user_amount_in_eth = Web3.fromWei(user_amount, 'ether')
        
        gtc_sig_app.logger.debug(f'user_id: {user_id}')
        gtc_sig_app.logger.debug(f'user_amount_in_gtc: {user_amount_in_eth}')
        gtc_sig_app.logger.debug(f'eth_signed_message_hash_hex: {eth_signed_message_hash_hex}')
        gtc_sig_app.logger.debug(f'eth_sign_message_sig_hex: {eth_signed_signature_hex}')
        gtc_sig_app.logger.debug(f'leaf hash: {leaf}')
        # gtc_sig_app.logger.debug(f'proof: {proof}')
       
        return_context = {
            "user_address" : user_address,
            "delegate_address" : delegate_address,
            "user_id" : user_id,
            "user_amount" : str(user_amount_in_eth),
            "eth_signed_message_hash_hex" : eth_signed_message_hash_hex,
            "eth_signed_signature_hex" : eth_signed_signature_hex,
            "leaf" : leaf,
            "proof" : proof
        }

        # could just return the object above but I like to know
        response = gtc_sig_app.response_class(
            response=json.dumps(return_context),
            status=200,
            mimetype='application/json'
        )

        # all is well, return response 
        return response
        
    # The HMAC didn't match, this should be considered suspicious & investigated in prod
    else: 
        gtc_sig_app.logger.info(f'HMAC hash did not match from IP: {ip_address} - This could be an attempt to generate a fraudulent claim!')
        return Response('{"message":"ESMS error"}', status=401, mimetype='application/json')
   
    # default catch/all return - this shouldn't ever hit  
    return Response('{"message":"HELLO-WORLD"}', status=200, mimetype='application/json')

def create_sha256_signature(key, message):
    '''
    Given key & message, returns HMAC digest of the message 
    User to verify that this POST was sent by with the key (gitcoin web)
    '''
    try:
        byte_key = binascii.unhexlify(key)
        message = message.encode()
        return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()
    except Exception as e:
        gtc_sig_app.logger.error(f'ESMS - Error Hashing Message: {e}')
        return False

def eth_sign(claim_msg):
    '''
    Signs an EIP712 compliant message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''
    signable_message = messages.encode_structured_data(claim_msg)
    signed_message = Account.sign_message(signable_message, private_key=gtc_sig_app.config.get("PRIVATE_KEY"))
    return signed_message.messageHash.hex(), signed_message.signature.hex()

def createSignableStruct(user_id, user_address, user_amount, delegate_address, leaf):
    '''
    crafts a signable struct using - https://github.com/ConsenSys/py-eip712-structs
    '''
    # Make a unique domain seperator - contract address is for the TokenDistributor
    domain = make_domain(
        name=gtc_sig_app.config.get("DOMAIN_NAME"),
        version=gtc_sig_app.config.get("DOMAIN_VERSION"),
        chainId=gtc_sig_app.config.get("DOMAIN_CHAIN_ID"),
        verifyingContract=gtc_sig_app.config.get("DOMAIN_CONTRACT")) 

    # Define our struct type
    class Claim(EIP712Struct):
        user_id = Uint(32)
        user_address = Address()
        user_amount = Uint(256)
        delegate_address = Address()
        leaf = Bytes(32)

    # Create an instance with some data
    claim = Claim(
        user_id=user_id,
        user_address=user_address,
        user_amount=user_amount,
        delegate_address=delegate_address,
        leaf=leaf)

    # Into message JSON - This method converts bytes types for you, which the default JSON encoder won't handle.
    claim_msg_dict = claim.to_message(domain)
    return claim_msg_dict

if __name__ == '__main__':
    gtc_sig_app.run()

