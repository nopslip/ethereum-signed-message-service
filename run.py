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

if "GTC_TOKEN_KEY" in os.environ:
    GTC_TOKEN_KEY = os.environ.get('GTC_TOKEN_KEY')
else: 
    shutdown_server('GTC_TOKEN_KEY not found!')

@gtc_sig_app.route('/')
def hello_world():
    return '--SERVER IS LIVE!--'

@gtc_sig_app.route('/v1/sign_claim', methods=['POST'])
def sign_claim():
    '''
    Provided payload of datas including, HMAC signature will return EIP712 compliant 
    struct that a user can use to claim tokens by sending to the a TokenDistributor contract
    '''
   
    # I think we will probably put in check to make sure this is gitcoin.co web server 
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
        user_address = json_request['user_address']
        user_id = json_request['user_id']
        user_amount = json_request['user_amount']
    except TypeError:
        gtc_sig_app.logger.info('Generic POST data TypeError received - confirm required values have been provided in POST payload')
        return Response("{'message':'NOT OKAY #5'}", status=400, mimetype='application/json')
    except Exception as e:
        gtc_sig_app.logger.error(f'GTC Claim Generator error: {e}')
        return Response("{'message':'NOT OKAY #6'}", status=400, mimetype='application/json') 
    
    
    # validate post body data - TODO - improve response to return valid json & proper status code 
    if not Web3.isAddress(user_address):
        gtc_sig_app.logger.info('Invalid user_address received!')
        return Response("{'message':'NOT OKAY #1'}", status=400, mimetype='application/json')
    # check we have an integer - improve me
    try:
        int(user_id)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_id received!')
        return Response("{'message':'NOT OKAY #2'}", status=400, mimetype='application/json')
    # check user id is an int - improve me 
    try: 
        int(user_amount)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_amount received!')
        return Response("{'message':'NOT OKAY #3'}", status=400, mimetype='application/json')
   
    # check if the hashes match for HMAC sig, if so, we can proceed to created eth signed message  
    if headers['X-GITCOIN-SIG'] == computed_hash:
        gtc_sig_app.logger.info('HASH MATCH!')
        
        # build out EIP712 struct 
        signable_message = createSignableStruct(user_id, user_address, user_amount)
        
        # sign it up 
        eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign_2(signable_message)

        gtc_sig_app.logger.info(f'eth_signed_message_hash_hex: {eth_signed_message_hash_hex}')
        gtc_sig_app.logger.info(f'eth_sign_message_sig_hex: {eth_signed_signature_hex}')
       
        return_context = {
            "user_address" : user_address,
            "user_id" : user_id,
            "user_amount" : user_amount,
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


@gtc_sig_app.route('/get_signature', methods=['POST'])
def get_signature():
    '''
    This is the legacy route used by the micro service to accept POST requests
    and return the transaction data required for users to claim GTC tokens.
    This route is be replaced with EIP712 compliant /v1/sign_claim
    '''

    # confirm we have our envars 
    if "GTC_SIG_KEY" in os.environ:
        GTC_SIG_KEY = os.environ.get('GTC_SIG_KEY')
    else: 
        gtc_sig_app.logger.info('GTC_SIG_KEY not found!')
        return "NO GTC_SIG_KEY FOUND!"

    if "GTC_TOKEN_KEY" in os.environ:
        GTC_TOKEN_KEY = os.environ.get('GTC_TOKEN_KEY')
    else: 
        gtc_sig_app.logger.info('GTC_TOKEN_KEY not found!')
        return "NO GTC_TOKEN_KEY FOUND!"
    
    # extract our headers 
    headers = request.headers

    # log headers for debugging 
    gtc_sig_app.logger.info(f'Incoming POST request headers:{request.headers}')
    
    # extract POST data as json 
    json_request = request.get_json()

    # log POST data for debugging 
    gtc_sig_app.logger.info(f'POST BODY DATA:{json_request}')
    
    # calc HMAC hash for our POST data
    computed_hash = create_sha256_signature(GTC_SIG_KEY, json.dumps(json_request))
    
    # log computed hash for debugging 
    gtc_sig_app.logger.info(f'COMPUTED HASH: {computed_hash}')

    # extract post data body
    user_address = json_request['user_address']
    user_id = json_request['user_id']
    user_amount = json_request['user_amount'] 
    
    # validate post body data - TODO - improve response to return valid json & proper status code 
    if not Web3.isAddress(user_address):
        gtc_sig_app.logger.info('Invalid user_address received!')
        return "THERE WAS AN ISSUE!"
    # check we have an integer - improve me
    try:
        int(user_id)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_id received!')
        return "THERE WAS AN ISSUE!"
    # check user id is an int - improve me 
    try: 
        int(user_amount)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_amount received!')
        return "THERE WAS AN ISSUE!"

    # if the hashes match, we proceed to created eth signed message  
    if headers['X-GITCOIN-SIG'] == computed_hash:
        gtc_sig_app.logger.info('HASH MATCH!')
        
        msg_hash_hex = keccak_hash(user_address, user_id, user_amount)
        gtc_sig_app.logger.info(f'got keccak: {msg_hash_hex}')
        
        eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign(msg_hash_hex, GTC_TOKEN_KEY)

        gtc_sig_app.logger.info(f'msg_hash_hex: {msg_hash_hex}')
        gtc_sig_app.logger.info(f'eth_signed_message_hash_hex: {eth_signed_message_hash_hex}')
        gtc_sig_app.logger.info(f'eth_sign_message_sig_hex: {eth_signed_signature_hex}')
        
        return_context = {
            "user_address" : user_address,
            "user_id" : user_id,
            "user_amount" : user_amount,
            "msg_hash_hex" : msg_hash_hex,
            "eth_signed_message_hash_hex" : eth_signed_message_hash_hex,
            "eth_signed_signature_hex" : eth_signed_signature_hex,
        }
        return return_context

    # oh no, the hashes didn't match.    
    else: 
        gtc_sig_app.logger.info('HASH NO MATCH!!')
        # TODO - set status code of 400 maybe?  
        return "THERE WAS AN ISSUE!"

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
        gtc_sig_app.logger.error(f'GTC Distributor - Error Hashing Message: {e}')
        return False 

def keccak_hash(user_address, user_id, user_amount):
    '''
    Provided user address, id, & token distribution amount
    returns solidity style keccak hash of the values - msg_hash_hex 
    '''
    # make sure our address is check summed 
    check_summed_address = Web3.toChecksumAddress(user_address)
    # TODO - make sure user id is legit, make sure amount is legit 
    
    # unsure why it returns bytes and/or what solidity will do this should suffice for now
    return Web3.toHex(Web3.solidityKeccak(['uint32', 'address', 'uint256'], [user_id, check_summed_address, user_amount]))
 

def eth_sign(msg_hash_hex, GTC_TOKEN_KEY):
    '''
    Signs a message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''
    message = messages.encode_defunct(hexstr=msg_hash_hex)
    signed_message = Account.sign_message(message, private_key=GTC_TOKEN_KEY)
    return signed_message.messageHash.hex(), signed_message.signature.hex()

def eth_sign_2(msg_json):
    '''
    Signs an EIP712 compliant message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''
    signable_message = messages.encode_structured_data(text=msg_json)
    signed_message = Account.sign_message(signable_message, private_key=GTC_TOKEN_KEY)
    return signed_message.messageHash.hex(), signed_message.signature.hex()

def createSignableStruct(user_id, user_address, user_amount):
    '''
    crafts a signable struct using - https://github.com/ConsenSys/py-eip712-structs
    '''

    # Make a unique domain seperator - contract addy is just random rinkeby address for me for testing 
    domain = make_domain(name='GTC', version='1.0.0', chainId=1, verifyingContract='0x8e9d312F6E0B3F511bb435AC289F2Fd6cf1F9C81')  

    # Define our struct type
    class ClaimStruct(EIP712Struct):
        user_id = Uint(32)
        user_address = Address()
        user_amount = Uint(256)

    # Create an instance with some data
    mine = ClaimStruct(user_id=user_id,user_address=user_address,user_amount=user_amount)

    # Into message JSON - domain required.
    # This method converts bytes types for you, which the default JSON encoder won't handle.
    my_msg_json = mine.to_message_json(domain)
  
    return my_msg_json


if __name__ == '__main__':
    gtc_sig_app.run()


