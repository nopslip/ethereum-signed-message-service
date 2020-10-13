from flask import Flask

gtc_sig_app = Flask(__name__)

@gtc_sig_app.route('/')
def hello_world():
    return 'Welcome!'

@gtc_sig_app.route('/get_signature', methods=['POST'])
def get_signature(request):
    headers = request.headers()
    data = request.get_data()
    print(headers)
    print(data)


if __name__ == '__main__':
    gtc_sig_app.run()
