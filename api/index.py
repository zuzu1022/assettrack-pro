import sys
import os
from pathlib import Path

# Get the project root directory
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Set working directory to the app directory
app_dir = project_root / "fixed_asset_register"
os.chdir(str(app_dir))

# Import the Flask app
from app import app as flask_app

# Export for Vercel
app = flask_app


