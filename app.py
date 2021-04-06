import os
import hmac
import hashlib
import binascii 
import json

from flask import Flask
from flask import request
from flask import Response

from web3 import Web3 
from eth_account import Account, messages

from eip712_structs import make_domain
from eip712_structs import EIP712Struct, Uint, Address, make_domain


gtc_sig_app = Flask(__name__)
gtc_sig_app.debug = True

# confirm we have our envars or don't start server 
if "GTC_SIG_KEY" in os.environ:
    GTC_SIG_KEY = os.environ.get('GTC_SIG_KEY')
else: 
    shutdown_server('No GTC_SIG_KEY found! Server will stop.')

if "PRIVATE_KEY" in os.environ:
    PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
else: 
    shutdown_server('PRIVATE_KEY not found!')

try:
    with open('dist_proofs.json') as d:
        gtc_sig_app.logger.info('Successfully opened dist_proofs.json')
        proofs = list(json.load(d).items())
        # print(proofs[0][1]['claim'])
        # print(proofs[0][1]['proof'])
except:
    gtc_sig_app.logger.error('There was an error opening proof claims file!')
    shutdown_server('ProofClaim file is required')

@gtc_sig_app.route('/')
def hello_world():
    return '--SERVER IS LIVE!--'

@gtc_sig_app.route('/v1/sign_claim', methods=['POST'])
def sign_claim():
    '''
    Provided payload of datas including, HMAC signature will return EIP712 compliant 
    struct that a user can use to claim tokens by sending to the a TokenDistributor contract
    '''
   
    # I think we will probably put in check to make sure this is gitcoin.co web server w
    # for now, we're just logging 
    ip_address = request.remote_addr
    gtc_sig_app.logger.info(f'Source IP: {ip_address}')

    # extract our headers, log headers for debugging 
    headers = request.headers
    gtc_sig_app.logger.info(f'Incoming POST request headers:{request.headers}')
    
    # extract POST data as json, log POST data for debugging 
    json_request = request.get_json()
    gtc_sig_app.logger.info(f'POST BODY DATA:{json_request}')
    
    # calc HMAC hash for our POST data, log computed hash for debugging 
    computed_hash = create_sha256_signature(GTC_SIG_KEY, json.dumps(json_request))
    gtc_sig_app.logger.info(f'COMPUTED HASH: {computed_hash}')
    
    # confirm we have POST data
    try: 
        user_id = json_request['user_id']
        user_address = json_request['user_address']
        user_amount = json_request['user_amount']
        delegate_address =  json_request['delegate_address']
    except TypeError:
        gtc_sig_app.logger.info('Generic POST data TypeError received - confirm required values have been provided in POST payload')
        return Response("{'message':'NOT OKAY #5'}", status=400, mimetype='application/json')
    except Exception as e:
        gtc_sig_app.logger.error(f'GTC Claim Generator error: {e}')
        return Response("{'message':'NOT OKAY #6'}", status=400, mimetype='application/json') 
        
    # validate post body data 
    if not Web3.isAddress(user_address):
        gtc_sig_app.logger.info('Invalid user_address received!')
        return Response("{'message':'NOT OKAY #1'}", status=400, mimetype='application/json')
    if not Web3.isAddress(delegate_address):
        gtc_sig_app.logger.info('Invalid delegate_address received!')
        return Response("{'message':'NOT OKAY #1.5'}", status=400, mimetype='application/json')
    # make sure user_id is an integer 
    try:
        int(user_id)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_id received!')
        return Response("{'message':'NOT OKAY #2'}", status=400, mimetype='application/json')
    # make sure it's an int
    try: 
        int(user_amount)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_amount received!')
        return Response("{'message':'NOT OKAY #3'}", status=400, mimetype='application/json')
    # get proof info for user
    try: 
        claim = proofs[user_id][1]['claim']
        proof = proofs[user_id][1]['proof']
        gtc_sig_app.logger.info(f'claim: {claim}')
        gtc_sig_app.logger.info(f'proof: {proof}')
    except:
        gtc_sig_app.logger.error('There was an error getting user claim proof!')
        return Response("{'message':'NOT OKAY #7'}", status=400, mimetype='application/json')
    # check if the hashes match for HMAC sig, if so, we can proceed to created eth signed message  
    if headers['X-GITCOIN-SIG'] == computed_hash:
        gtc_sig_app.logger.info('POST HMAC DIGEST MATCHES!')
        
        # build out EIP712 struct 
        signable_message = createSignableStruct(user_id, user_address, user_amount, delegate_address)
        
        # sign it up
        try:
            eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign_2(signable_message)
        except Exception as e:
            gtc_sig_app.logger.error(f'GTC Distributor - Error Hashing Message: {e}')
            return Response("{'message':'ERROR #1'}", status=500, mimetype='application/json')

        # this is a bit of hack to avoid bug in old web3 - ZW 11/1/2020
        # this will require that user_amount is not converted back to wei before tx is broadcast! 
        user_amount_in_eth = Web3.fromWei(user_amount, 'ether')
        
        gtc_sig_app.logger.info(f'user_amount_in_eth: {user_amount_in_eth}')
        gtc_sig_app.logger.info(f'eth_signed_message_hash_hex: {eth_signed_message_hash_hex}')
        gtc_sig_app.logger.info(f'eth_sign_message_sig_hex: {eth_signed_signature_hex}')
       
        return_context = {
            "user_address" : user_address,
            "delegate_address" : delegate_address,
            "user_id" : user_id,
            "user_amount" : str(user_amount_in_eth),
            "eth_signed_message_hash_hex" : eth_signed_message_hash_hex,
            "eth_signed_signature_hex" : eth_signed_signature_hex,
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
        gtc_sig_app.logger.info('HMAC HASH DID NOT MATCH!!')
        return Response("{'message':'NOT OKAY #4'}", status=401, mimetype='application/json')
    
    
    # default return 
    return Response("{'message':'OKAY!'}", status=200, mimetype='application/json')

@gtc_sig_app.before_request
def before_request():
    print(request.method, request.endpoint, request.data)


def shutdown_server(message):
    ''' 
    In the event that we want to kill the server (or prevent it from starting)
    '''
    gtc_sig_app.logger.info(message)
    raise RuntimeError(message)


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

def keccak_hash(user_address, user_id, user_amount):
    '''
    Provided user address, id, & token distribution amount
    returns solidity style keccak hash of the values - msg_hash_hex 
    '''
    # make sure our address is check summed 
    check_summed_address = Web3.toChecksumAddress(user_address)
    
    # unsure why it returns bytes and/or what solidity will do this should suffice for now
    return Web3.toHex(Web3.solidityKeccak(['uint32', 'address', 'uint256'], [user_id, check_summed_address, user_amount]))
 

def eth_sign(msg_hash_hex, PRIVATE_KEY):
    '''
    Signs a message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''
    message = messages.encode_defunct(hexstr=msg_hash_hex)
    signed_message = Account.sign_message(message, private_key=PRIVATE_KEY)
    return signed_message.messageHash.hex(), signed_message.signature.hex()

def eth_sign_2(claim_msg_json):
    '''
    Signs an EIP712 compliant message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''
    signable_message = messages.encode_structured_data(text=claim_msg_json)
    signed_message = Account.sign_message(signable_message, private_key=PRIVATE_KEY)
    return signed_message.messageHash.hex(), signed_message.signature.hex()

def createSignableStruct(user_id, user_address, user_amount, delegate_address):
    '''
    crafts a signable struct using - https://github.com/ConsenSys/py-eip712-structs
    '''

    # Make a unique domain seperator - contract addy is for the TokenDistributor 
    domain = make_domain(
        name='WOLF', 
        version='1.0.1', 
        chainId=4, 
        verifyingContract='0x8c81B26d50fd12E8979D98231d40948bec50cF3C')  

    # Define our struct type
    class Claim(EIP712Struct):
        user_id = Uint(32)
        user_address = Address()
        user_amount = Uint(256)
        delegate_address = Address()

    # Create an instance with some data
    claim = Claim(
        user_id=user_id,
        user_address=user_address,
        user_amount=user_amount, 
        delegate_address=delegate_address)

    # Into message JSON - This method converts bytes types for you, which the default JSON encoder won't handle.
    claim_msg_json = claim.to_message_json(domain)
  
    return claim_msg_json


if __name__ == '__main__':
    gtc_sig_app.run()


