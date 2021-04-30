## Ethereum Signed Message Service 

- ESMS was created to distribute GTC tokens to the Gitcoin ecosystem. 

- ESMS is a flask based HTTPS micro service that accepts token claim metadata and returns a signed claim message, merkle leaf, proofs, and original metadata that a user can broadcast to TokenDistributor contract to redeem token claim.  

### Features 

HMAC authentication is used to verify the integrity of sender by requiring a valid HMAC signature in the HTTP headers of the request. 


### Setup & Config 

1) create & activate Python virtual environment 
2) download the repository 
3) install requirements   
4) set environmental variables:  
  - copy sample.env .env and configure accordingly  
  - two envars are left to be set on the command line:

    `PRIVATE_KEY` & `GTC_SIG_KEY`

`GTC_SIG_KEY` is the HMAC secret/key 

`PRIVATE_KEY` is the private key to the ETH account used to sign claims (pub key to this private key will be hardcoded into the token distribution contract) 

### Run app 

testing/Dev:
`flask run`

production:
`gunicorn app:gtc_sig_app`







