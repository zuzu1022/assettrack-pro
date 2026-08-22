import sys
import os
from pathlib import Path

# Get the project root directory
project_root = Path(__file__).parent.parent
fixed_asset_path = project_root / "fixed_asset_register"

# Add paths to Python
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(fixed_asset_path))

# Set working directory
os.chdir(str(fixed_asset_path))

# Set environment variable to prevent database initialization issues
os.environ['FLASK_ENV'] = 'production'

try:
    # Import Flask app
    from app import app
    
    # Disable debug mode for serverless
    app.config['DEBUG'] = False
    
except Exception as e:
    # Create a minimal app if import fails
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return {'error': str(e), 'type': type(e).__name__}, 500



