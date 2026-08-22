import os

# Statically present top-level names for deployment detection
application = None
handler = None

# Prefer a static import so hosting providers can statically detect the callable.
try:
    from fixed_asset_register.app import app as _imported_app
    application = _imported_app
    handler = _imported_app
except Exception:
    # Minimal fallback if import fails at runtime; log traceback to help debugging.
    import traceback
    print("Failed to import fixed_asset_register.app:", flush=True)
    print(traceback.format_exc(), flush=True)
    from flask import Flask, jsonify
    fallback = Flask(__name__)

    @fallback.route('/')
    def fallback_index():
        return jsonify({'error': 'Failed to import application'}), 500

    application = fallback
    handler = fallback

