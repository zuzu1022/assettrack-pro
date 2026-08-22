import sys
import os
from pathlib import Path

# Get the project root directory
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "fixed_asset_register"))

# Set working directory to the app directory
app_dir = project_root / "fixed_asset_register"
os.chdir(str(app_dir))

try:
    # Import the Flask app
    from app import app
except ImportError as e:
    print(f"Error importing app: {e}")
    raise

# Vercel expects the app to be exported as 'app'
# No need to wrap it - Vercel's Python runtime handles WSGI apps natively


