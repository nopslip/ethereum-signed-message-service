# -*- coding: utf-8 -*-
"""Create EIP712 struct from https://github.com/ConsenSys/py-eip712-structs 

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

from eip712_structs import EIP712Struct, Uint, Address, make_domain
from eth_account import Account, messages

# test and already public private key for account 0x3DB763BBBb1aC900EB2eB8b106218f85F9f64a13 
GTC_TOKEN_KEY = '7bf19806aa6d5b31d7b7ea9e833c202e51ff8ee6311df6a036f0261f216f09ef'

# test values to populate 
user_address = '0x8e9d312F6E0B3F511bb435AC289F2Fd6cf1F9C81'
user_id = 42
user_amount = 1000000000000000

def createSignableStruct():
    '''
    crafts a signable struct using - https://github.com/ConsenSys/py-eip712-structs
    '''
    
    # Make a unique domain seperator - contract addy is just random rinkeby address for me for testing 
    domain = make_domain(name='GTC-TokenDistributor', version='1.0.0', chainId=1, verifyingContract='0x8e9d312F6E0B3F511bb435AC289F2Fd6cf1F9C81')  

    # Define your struct type
    class ClaimStruct(EIP712Struct):
        user_address = Address()
        user_id = Uint(32)
        user_amount = Uint(256)

    # Create an instance with some data
    mine = ClaimStruct(user_address=user_address, user_id=user_id, user_amount=user_amount)

    # Values can be get/set dictionary-style:
    # mine['some_number'] = 4567
    # assert mine['some_string'] == 'hello world'
    # assert mine['some_number'] == 4567

    # Into a message dict - domain required
    my_msg = mine.to_message(domain)

    # Into message JSON - domain required.
    # This method converts bytes types for you, which the default JSON encoder won't handle.
    my_msg_json = mine.to_message_json(domain)

    # Into signable bytes - domain required
    my_bytes = mine.signable_bytes(domain)

    return my_msg_json


def eth_sign(msg_json, GTC_TOKEN_KEY):
    '''
    Signs a message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''
    signable_message = messages.encode_structured_data(text=msg_json)
    signed_message = Account.sign_message(signable_message, private_key=GTC_TOKEN_KEY)
    return signed_message.messageHash.hex(), signed_message.signature.hex()


# the magic 
eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign(createSignableStruct(), GTC_TOKEN_KEY)
print(eth_signed_message_hash_hex, eth_signed_signature_hex)