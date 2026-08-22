"""
Serverless Flask WSGI handler for Vercel
"""
import sys
import os
from pathlib import Path

# Setup paths
project_root = Path(__file__).parent.parent
fixed_asset_path = project_root / "fixed_asset_register"
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(fixed_asset_path))
os.chdir(str(fixed_asset_path))

# Set environment for serverless
os.environ['FLASK_ENV'] = 'production'
os.environ['WERKZEUG_RUN_MAIN'] = 'true'

# Global app instance (lazy-loaded)
_app = None

def get_app():
    """Lazily load and return the Flask app"""
    global _app
    if _app is not None:
        return _app
    
    try:
        from app import app
        _app = app
        # Disable debug mode in serverless
        _app.config['DEBUG'] = False
        return _app
    except Exception as e:
        # Return error app if import fails
        from flask import Flask, jsonify
        error_app = Flask(__name__)
        error_msg = str(e)
        
        @error_app.errorhandler(Exception)
        def handle_error(e):
            return jsonify({'error': 'App failed to initialize', 'details': str(e)}), 500
        
        @error_app.route('/')
        @error_app.route('/<path:path>')
        def catch_all(path=''):
            return jsonify({'error': 'App initialization failed', 'message': error_msg}), 500
        
        return error_app

# Vercel calls this WSGI app
app = get_app()
