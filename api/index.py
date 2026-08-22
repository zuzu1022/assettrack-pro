import os
import sys
from pathlib import Path

# Setup environment
os.environ.setdefault('FLASK_ENV', 'production')

# Setup Python path
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "fixed_asset_register"))
os.chdir(str(root / "fixed_asset_register"))

# Import Flask
from flask import Flask, jsonify

try:
    # Try importing the main app
    from app import app
    
    # Configure for production
    app.config['DEBUG'] = False
    app.config['ENV'] = 'production'
    
    print("Successfully imported main app from fixed_asset_register/app.py", flush=True)
    
except Exception as e:
    # Fallback to minimal app if import fails
    import traceback
    error_msg = traceback.format_exc()
    print(f"Failed to import main app: {error_msg}", flush=True)
    
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return jsonify({
            'error': 'Failed to import main application',
            'message': str(e),
            'type': type(e).__name__,
            'traceback': error_msg
        }), 500

# Expose WSGI/ASGI callable names expected by various hosts (Vercel expects one of these)
try:
    application = app
    handler = app
    print("Exposed WSGI application as 'application' and 'handler'", flush=True)
except NameError:
    # Fallback minimal app if somehow `app` wasn't created
    fallback = Flask(__name__)

    @fallback.route('/')
    def fallback_index():
        return jsonify({'error': 'No application available'}), 500

    application = fallback
    handler = fallback

