import os

# Prefer a static import so hosting providers can statically detect the callable.
# Import the Flask `app` from the package and expose it as `application` and `handler`.
try:
    from fixed_asset_register.app import app as application
    handler = application
except Exception:
    # Minimal fallback if import fails at runtime; kept simple for static analysis.
    from flask import Flask, jsonify
    fallback = Flask(__name__)

    @fallback.route('/')
    def fallback_index():
        return jsonify({'error': 'Failed to import application'}), 500

    application = fallback
    handler = fallback

