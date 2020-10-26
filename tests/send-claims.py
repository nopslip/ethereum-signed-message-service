# -*- coding: utf-8 -*-
"""Fire off test POSTs to the signing server 

Copyright (C) 2020 Gitcoin Core

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

"""

import requests
import json
import hmac
import hashlib
import binascii

v1_api_uri = 'https://gtc-request-signer.herokuapp.com/v1/sign_claim'
dev_hmac_key = 'E49756B4C8FAB4E48222A3E7F3B97CC3'

def test_post_values_2():
    '''
    working post data
    '''

    post_data = {}
    post_data['user_id'] = 42
    post_data['user_address'] = '0x8e9d312F6E0B3F511bb435AC289F2Fd6cf1F9C81'
    post_data['user_amount'] = 1000000000000000 # placeholder for amount, need to use big number 

    computed_hash = create_sha256_signature(dev_hmac_key, json.dumps(post_data))

    header = { 
        "X-GITCOIN-SIG" : computed_hash,
        "content-type": "application/json",
    }

    r = requests.post(v1_api_uri, data=json.dumps(post_data), headers=header)

    print(f'test_post_values_2: {r.text}')
    # assert r.status_code == 400, "Empty Post data should return a 400!"


def test_post_values_1():
    '''
    Send empty required POST data and confirm response is 400
    '''
    r = requests.post(v1_api_uri, data = {'key':'value'})
    print(f'test_post_values_1: {r.text}')
    assert r.status_code == 400, "Empty Post data should return a 400!"


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
        print(f'GTC Distributor - Error Hashing Message: {e}')
        return False 

# run our tests 
# test_post_values_1()
test_post_values_2()





