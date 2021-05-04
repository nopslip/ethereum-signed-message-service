## Ethereum Signed Message Service 

- ESMS was created to distribute GTC tokens to the Gitcoin ecosystem. 

- ESMS is a flask based HTTPS micro service that accepts token claim metadata and returns a signed claim message, merkle leaf, proofs, and original metadata that a user can broadcast to TokenDistributor contract to redeem token claim.  

### Features/Design

- NGINX-->Gunincorn-->ESMS  

- HMAC authentication is used to verify the integrity of sender by requiring a valid HMAC signature in the HTTP headers of the request. 


### Setup & Config

First setup a server to run the ESMS on. 

#### Reverse Proxy
1) install Nginx

> `sudo apt install nginx`

Nginx can easily be used to expose/proxy to one or more instances of the ESMS. Both of the examples below assume nginx.conf will have a line like:

 `include /etc/nginx/conf.d/*.conf;`

 Then your config file(s) live in: `/etc/nginx/conf.d/`

[NGINX proxy config for dev and staging](./nginx-configs/esms-dev.conf)

Or:

[NGINX proxy for config for production](./nginx-configs/esms-prod.conf) 

2) Install Certbot 

Best to check Certbot official docs as install instructions seem to change frequently. https://certbot.eff.org/instructions  

For reference, this guide for Ubuntu20 was used for our setup: https://certbot.eff.org/lets-encrypt/ubuntufocal-nginx

> `sudo snap install core; sudo snap refresh core`

> `sudo snap install --classic certbot` 

> `sudo ln -s /snap/bin/certbot /usr/bin/certbot`

> `sudo snap set certbot trust-plugin-with-root=ok` (can't recall why I needed this. Leaving here for reference)

> `sudo certbot --nginx`


#### ESMS Service 
1) create & activate Python virtual environment 

> `sudo apt install python3-pip`

> `sudo apt-get install python3-venv`

> `python3 -m venv esms_venv`

> `source esms_venv/bin/activate`

> `pip install -U Flask`

> `sudo apt-get install gunicorn`

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

### Security Considerations 

1) Restrict access to port 80/443 to only trusted app IP(s) 
2) Collect ESMS logs 
3) non-default SSH port 
4) user mgmt - no shared logins! ;), ssh keys et
5) etc, todo








