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
    # Minimal fallback if import fails at runtime; kept simple for static analysis.
    from flask import Flask, jsonify
    fallback = Flask(__name__)

    @fallback.route('/')
    def fallback_index():
        return jsonify({'error': 'Failed to import application'}), 500

    application = fallback
    handler = fallback

