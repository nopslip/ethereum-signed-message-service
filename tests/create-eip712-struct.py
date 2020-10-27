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
from web3 import Web3
from pprint import pprint
import json

# test and already public private key for account 0x3DB763BBBb1aC900EB2eB8b106218f85F9f64a13 
GTC_TOKEN_KEY = '7bf19806aa6d5b31d7b7ea9e833c202e51ff8ee6311df6a036f0261f216f09ef'

# test values to populate 
user_id = 26
user_address = '0x8e9d312F6E0B3F511bb435AC289F2Fd6cf1F9C81'
user_amount = 1000000000000000

def createSignableStruct():
    '''
    crafts a signable struct using - https://github.com/ConsenSys/py-eip712-structs
    '''

    # Make a unique domain seperator - contract addy is just random rinkeby address for me for testing 
    
    domain = make_domain(
        name='GTC', 
        version='1.0.0', 
        chainId=1, 
        verifyingContract='0x8e9d312F6E0B3F511bb435AC289F2Fd6cf1F9C81')
    

    # Define your struct type
    class Claim(EIP712Struct):
        user_id = Uint(32)
        user_address = Address()
        user_amount = Uint(256)
        
    # Create a claim instance with some data
    claim = Claim(
        user_id=user_id,
        user_address=user_address,
        user_amount=user_amount)

    # matching in solidity YES
    GTC_TOKEN_CLAIM_TYPEHASH = Web3.toHex(Web3.solidityKeccak(['string'], ["Claim(uint32 user_id,address user_address,uint256 user_amount)"]))
    pprint(f'GTC_TOKEN_CLAIM_TYPEHASH: {GTC_TOKEN_CLAIM_TYPEHASH}')

    # not yet matching in Solidity 
    # EIP712_TYPEHASH = Web3.toHex(Web3.solidityKeccak(['string'], ["EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"]))
    # pprint(f'DOMAIN_TYPEHASH: {EIP712_TYPEHASH}')

    # check_summed_address = Web3.toChecksumAddress(user_address)
    
    # not yet matching 
    CLAIM_HASH = Web3.toHex(Web3.solidityKeccak(['bytes32', 'uint32', 'address', 'uint256'], [GTC_TOKEN_CLAIM_TYPEHASH, claim['user_id'], claim['user_address'], claim['user_amount']]))
    pprint(f'CLAIM_HASH: {CLAIM_HASH}')

  
    # Into a message dict - domain required
    claim_msg = claim.to_message(domain)
    assert isinstance(claim_msg, dict)
    pprint(f'claim_msg: {claim_msg}')

    # This method converts bytes types for you, which the default JSON encoder won't handle.
    claim_msg_json = claim.to_message_json(domain)
    assert isinstance(claim_msg_json, str)
    pretty_json = json.dumps(json.loads(claim_msg_json), indent=2)
    pprint(f'claim_msg_json: {pretty_json}')

    # Into signable bytes - domain required
    claim_bytes = claim.signable_bytes(domain)
    pprint(f'claim_bytes: {claim_bytes}')
    digest = Web3.toHex(Web3.solidityKeccak(['bytes'], [claim_bytes]))
    pprint(f'digest lord: {digest}') 
    
    return claim_msg_json


def eth_sign(claim_msg_json, GTC_TOKEN_KEY):
    '''
    Signs a message using Ethereum private key
    returns messageHash in HexBytes & signature in HexBytes
    '''    
    signable_message = messages.encode_structured_data(text=claim_msg_json)
    pprint(f'signable_message: {signable_message}')
    signed_message = Account.sign_message(signable_message, private_key=GTC_TOKEN_KEY)
    pprint(f'full monty: {signed_message}')
    # print(f's,r: {signed_message.s.hex()}, {signed_message.r.hex()}')
    return signed_message.messageHash.hex(), signed_message.signature.hex()


def keccak_hash(user_id, user_address, user_amount):
    '''
    Provided user address, id, & token distribution amount
    returns solidity style keccak hash of the values - msg_hash_hex 
    '''
    # make sure our address is check summed 
    check_summed_address = Web3.toChecksumAddress(user_address)
     
    # unsure why it returns bytes and/or what solidity will do this should suffice for now
    return Web3.toHex(Web3.solidityKeccak(['uint32', 'address', 'uint256'], [user_id, check_summed_address, user_amount]))

# the solidity style hash 
# pprint(keccak_hash(user_id=user_id, user_address=user_address, user_amount=user_amount))

# the magic 
eth_signed_message_hash_hex, eth_signed_signature_hex = eth_sign(createSignableStruct(), GTC_TOKEN_KEY)
# print(eth_signed_message_hash_hex, eth_signed_signature_hex)
print('\n\n\n')