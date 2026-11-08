"""Flask API for public-target passive security reviews."""
import hmac
import logging
import os
import threading
import time
from collections import OrderedDict, deque

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from scanner import WebSecurityScanner
from targets import UnsafeTarget

logger = logging.getLogger(__name__)


class ScanGuard:
    """Bounded per-process admission control; add shared limits at the edge."""
    def __init__(self):
        self.lock = threading.Lock()
        self.clients = OrderedDict()
        self.slots = threading.BoundedSemaphore(2)

    def admit(self, client):
        now = time.monotonic()
        with self.lock:
            timestamps = self.clients.pop(client, deque())
            while timestamps and now - timestamps[0] >= 60:
                timestamps.popleft()
            allowed = len(timestamps) < 5
            if allowed:
                timestamps.append(now)
            self.clients[client] = timestamps
            while len(self.clients) > 4096:
                self.clients.popitem(last=False)
            return allowed


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=8192, SCANNER_API_KEY=os.environ.get("SCANNER_API_KEY", ""))
    if test_config:
        app.config.update(test_config)
    origins = [item.strip() for item in os.environ.get("SCANNER_ALLOWED_ORIGINS", "").split(",") if item.strip()]
    if "*" in origins:
        raise ValueError("SCANNER_ALLOWED_ORIGINS must contain explicit origins, not '*'.")
    if origins:
        CORS(app, resources={r"/scan": {"origins": origins}}, methods=["POST"], allow_headers=["Content-Type", "Authorization"])
    guard = ScanGuard()
    app.extensions["scan_guard"] = guard

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.name), exc.code

    @app.get("/health")
    def health():
        return jsonify(status="ok", version="2.0", mode="passive")

    @app.post("/scan")
    def scan_route():
        api_key = app.config["SCANNER_API_KEY"]
        expected = f"Bearer {api_key}".encode()
        if api_key and not hmac.compare_digest(request.headers.get("Authorization", "").encode(), expected):
            return jsonify(error="A valid API bearer token is required."), 401
        if not request.is_json:
            return jsonify(error="Content-Type must be application/json."), 415
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify(error="The request body must be a JSON object."), 400
        if data.get("authorized") is not True:
            return jsonify(error="Confirm that you own the target or have permission to scan it (authorized: true)."), 400
        if set(data) - {"url", "authorized", "max_urls", "max_depth"}:
            return jsonify(error="Unknown scan options. Supported options: url, authorized, max_urls, max_depth."), 400
        max_urls, max_depth = data.get("max_urls", 10), data.get("max_depth", 2)
        if type(max_urls) is not int or not 1 <= max_urls <= 20 or type(max_depth) is not int or not 0 <= max_depth <= 3:
            return jsonify(error="max_urls must be an integer from 1 to 20; max_depth must be an integer from 0 to 3."), 400
        try:
            scanner = WebSecurityScanner(data.get("url"), max_urls=max_urls, max_depth=max_depth)
        except UnsafeTarget as exc:
            return jsonify(error=str(exc)), 400
        if not guard.admit(request.remote_addr or "unknown"):
            response = jsonify(error="Too many scans. Try again in one minute.")
            response.headers["Retry-After"] = "60"
            return response, 429
        if not guard.slots.acquire(blocking=False):
            response = jsonify(error="The scanner is busy. Try again shortly.")
            response.headers["Retry-After"] = "10"
            return response, 503
        try:
            report = scanner.scan()
            if not report["scanned_urls"]:
                return jsonify(error="No pages could be analyzed. Review the scan warnings.", **report), 422
            return jsonify(report)
        except Exception:
            logger.error("Scan failed with an unexpected internal error")
            return jsonify(error="The scan failed unexpectedly. Please try again later."), 500
        finally:
            guard.slots.release()

    return app


app = create_app()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=False, host="127.0.0.1", port=5000)
