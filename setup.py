import os

def shutdown_server(message):
    ''' Generic function to prevent app from starting.'''
    raise RuntimeError(message)

if "GTC_SIG_KEY" in os.environ:
    GTC_SIG_KEY = os.environ.get('GTC_SIG_KEY')
else:
    shutdown_server('GTC_SIG_KEY is required.')

if "PRIVATE_KEY" in os.environ:
    PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
else:
    shutdown_server('PRIVATE_KEY is required.')

if "DOMAIN_NAME" in os.environ:
    DOMAIN_NAME = os.environ.get('DOMAIN_NAME')
else:
    shutdown_server('DOMAIN_NAME is required.')

if "DOMAIN_VERSION" in os.environ:
    DOMAIN_VERSION = os.environ.get('DOMAIN_VERSION')
else:
    shutdown_server('DOMAIN_VERSION is required.')

if "DOMAIN_CHAIN_ID" in os.environ:
    DOMAIN_CHAIN_ID = os.environ.get('DOMAIN_CHAIN_ID')
else:
    shutdown_server('DOMAIN_CHAIN_ID is required.')

if "DOMAIN_CONTRACT" in os.environ:
    DOMAIN_CONTRACT = os.environ.get('DOMAIN_CONTRACT')
else:
    shutdown_server('DOMAIN_CONTRACT is required.')
