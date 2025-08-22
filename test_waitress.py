from waitress import serve
from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return 'OK'

if __name__ == '__main__':
    print('Starting Waitress on port 5004...')
    serve(app, host='0.0.0.0', port=5004)
