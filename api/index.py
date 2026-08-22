import os
import sys
from pathlib import Path

# Setup Python path
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "fixed_asset_register"))

# Create minimal Flask app first
from flask import Flask

app = Flask(__name__)

# Test route
@app.route('/')
def hello():
    return 'Flask app is working!'

# Test route 2  
@app.route('/test')
def test():
    return {'status': 'ok', 'message': 'Flask is running on Vercel'}

