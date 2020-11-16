## Ethereum Signed Message Service 

ESMS is a flask based HTTPS micro service that accepts metadata and returns a signed message. Provided the conditions are met, ESMS will return a valid EIP712 signed message signature and hash with the original metadata. 

HMAC authentication is used to verify the integrity of sender by requiring a valid HMAC signature in the HTTP headers of the request. 

ESMS was created to distribute GTC tokens to the Gitcoin ecosystem. You can find more info on how ESMS is used in that context 
[here](https://github.com/nopslip/gov-token/blob/master/info/TOKENDISTRIBUTOR.md). 

### Setup & Config 
ESMS v0 is is built to run on Heroku. You should be able to deploy and go.  Some envars are needed though: 

```
heroku config
```

Returns: 

```
FLASK_ENV:     development
GTC_SIG_KEY:   E49756B4C8FAB4E48222A3E7F3B97CC3
PRIVATE_KEY:   e33b70cc2715246e0b5edb49e51d7e05aa6a6a056679204d314932ce22c72edf
```

**where `GTC_SIG_KEY` is for HMAC amd `PRIVATE_KEY` is for Ethereum signed message**


