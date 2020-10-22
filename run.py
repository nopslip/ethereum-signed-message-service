import os
import hmac
import hashlib
import binascii 
import json

from eth_account import Account, messages
from flask import Flask
from flask import request
from web3 import Web3 

gtc_sig_app = Flask(__name__)

@gtc_sig_app.route('/')
def hello_world():
    return '--GTC TOKEN SIGNER V1--'

@gtc_sig_app.route('/get_signature', methods=['POST'])
def get_signature():
    '''
    This is the main route used by the micro service to accept POST requests
    and return the transaction data required for users to claim GTC tokens
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
    
    try:
        int(user_id)
    except ValueError:
        gtc_sig_app.logger.info('Invalid user_id received!')
        return "THERE WAS AN ISSUE!"
    
    # this should be improved probably 
    if user_amount.isdigit():
        gtc_sig_app.logger.info('Invalid user_amount received!')
        return "THERE WAS AN ISSUE!"


    # if the hashes match, we proceed to created eth signed message  
    if headers['X-GITCOIN-SIG'] == computed_hash:
        gtc_sig_app.logger.info('HASH MATCH!')
        
        msg_hash_hex = keccak_hash(user_address, user_id, user_amount)
        gtc_sig_app.logger.info(f'got keccak: {msg_hash_hex}')
        
        eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign(msg_hash_hex, GTC_TOKEN_KEY)

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


if __name__ == '__main__':
    gtc_sig_app.run()
