import os
import hmac
import hashlib
import binascii 
import json

from flask import Flask
from flask import request

gtc_sig_app = Flask(__name__)

@gtc_sig_app.route('/')
def hello_world():
    return '--GTC TOKEN SIGNER V1--'

@gtc_sig_app.route('/get_signature', methods=['POST'])
def get_signature():

    # todo - what if key doesn't exist?
    GTC_SIG_KEY = os.environ.get('GTC_SIG_KEY')
    
    headers = request.headers
    gtc_sig_app.logger.info(f'HEADERS:{headers}')
    
    dict = request.form
    gtc_sig_app.logger.info(f'POST BODY DATA:{dict}')

    for key in dict:
        print(f'form key - {key}')
        print(f'key value - {dict[key]}')

    print(f'GTC_SIG_KEY: {os.environ.get("GTC_SIG_KEY")}')
    
    computed_hash = create_sha256_signature(GTC_SIG_KEY, json.dumps(dict))
    
    gtc_sig_app.logger.info(f'COMPUTED HASH: {computed_hash}')

    if headers['X-GITCOIN-SIG'] == computed_hash:
        gtc_sig_app.logger.info('HASH MATCH!')
    else: 
        gtc_sig_app.logger.info('HASH NO MATCH!!')

    # we must respond to the request  
    return "THIS WILL BE A SIGNED MESSAGE!"

def create_sha256_signature(key, message):
    '''
    Given key & message, returns HMAC digest of the message 
    '''
    try:
        byte_key = binascii.unhexlify(key)
        message = message.encode()
        return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()
    except Exception as e:
        gtc_sig_app.logger.error(f'GTC Distributor - Error Hashing Message: {e}')
        return False 


if __name__ == '__main__':
    gtc_sig_app.run()
