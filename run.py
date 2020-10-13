import os
import hmac
import hashlib
import binascii 
from flask import Flask
from flask import request

gtc_sig_app = Flask(__name__)

@gtc_sig_app.route('/')
def hello_world():
    return '--GTC TOKEN SIGNER V1--'

@gtc_sig_app.route('/get_signature', methods=['POST'])
def get_signature():
    headers = request.headers
    print(headers)
    
    dict = request.form
    for key in dict:
        print(f'form key - {key}')
        print(f'key value - {dict[key]}')

    print(f'GTC_SIG_KEY: {os.environ.get("GTC_SIG_KEY")}')
    
    '''
    try:
        GTC_SIG_KEY = os.environ.get('GTC_SIG_KEY')
        if headers['X-GITCOIN-SIG'] == 
     except:
    '''

    # we must respond to the request  
    return "THIS WILL BE A SIGNED MESSAGE!"

def create_sha256_signature(key, message):
    '''
    Given key & message, returns HMAC digest of the message 
    '''
    byte_key = binascii.unhexlify(key)
    message = message.encode()
    return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()


if __name__ == '__main__':
    gtc_sig_app.run()
