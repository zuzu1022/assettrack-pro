import os
import sys
from pathlib import Path

# Statically present top-level names for deployment detection
application = None
handler = None

# Ensure the application package is importable when running on the platform
root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / "fixed_asset_register"))
os.chdir(str(root / "fixed_asset_register"))

# Prefer a static import so hosting providers can statically detect the callable.
try:
    from fixed_asset_register.app import app as _imported_app
    application = _imported_app
    handler = _imported_app
except Exception:
    # Minimal fallback if import fails at runtime; log traceback to help debugging.
    import traceback
    import_error = traceback.format_exc()
    print("Failed to import fixed_asset_register.app:", flush=True)
    print(import_error, flush=True)
    from flask import Flask, jsonify
    fallback = Flask(__name__)

    @fallback.route('/')
    def fallback_index():
        return jsonify({'error': 'Failed to import application', 'traceback': import_error}), 500

    application = fallback
    handler = fallback

