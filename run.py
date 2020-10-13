from flask import Flask
from flask import request

gtc_sig_app = Flask(__name__)

@gtc_sig_app.route('/')
def hello_world():
    return 'Welcome!'

@gtc_sig_app.route('/get_signature', methods=['POST'])
def get_signature():
    headers = request.headers
    print(headers)
    
    dict = request.form
    for key in dict:
        print(f'form key {dict[key]}')
    
    content = "yah!"
    return content, status.HTTP_200_OK

if __name__ == '__main__':
    gtc_sig_app.run()
