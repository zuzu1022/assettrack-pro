import sys
import os

# Test imports
test_results = {}

try:
    import flask
    test_results['flask'] = 'OK'
except Exception as e:
    test_results['flask'] = str(e)

try:
    from pathlib import Path
    test_results['pathlib'] = 'OK'
except Exception as e:
    test_results['pathlib'] = str(e)

try:
    from flask import Flask, jsonify
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return jsonify(test_results)
    
except Exception as e:
    from http.server import BaseHTTPRequestHandler
    class handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"error": "' + str(e).encode() + b'"}')

