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
from flask import Flask

try:
    # Try importing the main app
    from app import app
    
    # Configure for production
    app.config['DEBUG'] = False
    app.config['ENV'] = 'production'
    
except Exception as e:
    # Fallback to minimal app if import fails
    print(f"Failed to import main app: {e}", flush=True)
    
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return {
            'error': 'Failed to import main application',
            'message': str(e),
            'type': type(e).__name__
        }, 500

