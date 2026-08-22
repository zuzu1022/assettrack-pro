import sys
import os
from pathlib import Path

# Setup paths
project_root = Path(__file__).parent.parent
fixed_asset_path = project_root / "fixed_asset_register"
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(fixed_asset_path))
os.chdir(str(fixed_asset_path))

# Set environment
os.environ['FLASK_ENV'] = 'production'

from flask import Flask, jsonify

app = Flask(__name__)

# Try to import the real app
try:
    from app import app as real_app
    app = real_app
    app.config['DEBUG'] = False
except ImportError as e:
    @app.route('/')
    def error():
        return jsonify({'error': str(e), 'type': 'ImportError'}), 500

