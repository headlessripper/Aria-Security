import os
import secrets
import json
import threading
import ssl
from pathlib import Path
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from Main_Unit.Config.Sys_Config import PAIR_PORT, MY_IP

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)

# threading mode so ssl_context works
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=False,
    engineio_logger=False,
    async_mode="threading",
)

# Globals
PAIRING_TOKEN = None
SESSION_TOKENS = set()
TOKENS_EXPIRY = {}
SENTINEL_SERVICE = None  # injected from SentinelService

CERT_DIR = Path("certs")
CERT_PATH = CERT_DIR / "sentinel.pem"
KEY_PATH = CERT_DIR / "sentinel.key"


def generate_self_signed_cert(cert_path=str(CERT_PATH), key_path=str(KEY_PATH)):
    """Auto-generate self-signed cert if missing."""
    CERT_DIR.mkdir(exist_ok=True)
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print("🔐 Generating self-signed cert...")
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ZA"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Gauteng"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Ennerdale"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Aria"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Aria Security"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("✅ Certs generated at:", CERT_PATH, KEY_PATH)


generate_self_signed_cert()


def generate_pairing_token():
    global PAIRING_TOKEN
    PAIRING_TOKEN = secrets.token_urlsafe(32)
    print("🔑 New PAIRING_TOKEN:", PAIRING_TOKEN)
    print("🌐 Pair at: https://%s:%s" % (MY_IP, PAIR_PORT))
    return PAIRING_TOKEN


def cleanup_expired_tokens():
    now = datetime.utcnow()
    expired = [t for t, exp in TOKENS_EXPIRY.items() if now > exp]
    for t in expired:
        SESSION_TOKENS.discard(t)
        TOKENS_EXPIRY.pop(t, None)


def require_auth(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        cleanup_expired_tokens()
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth[7:]  # strip "Bearer "
        if token not in SESSION_TOKENS:
            return jsonify({"error": "Invalid/expired token"}), 401
        return f(*args, **kwargs)

    return decorated


@app.route("/", methods=["GET"])
def index():
    """Web console UI."""
    return render_template("index.html")


# NEW: internal route so desktop app can fetch pairing token without QR
@app.route("/auth/internal_pair_token", methods=["GET"])
def internal_pair_token():
    global PAIRING_TOKEN
    if PAIRING_TOKEN is None:
        generate_pairing_token()
    return jsonify({"pairing_token": PAIRING_TOKEN})


@app.route("/auth/pair", methods=["POST"])
def pair():
    data = request.get_json(silent=True) or {}
    print("🔗 /auth/pair request:", data)
    if data.get("pairing_token") != PAIRING_TOKEN:
        print("❌ Invalid pairing token:", data.get("pairing_token"))
        return jsonify({"error": "Invalid pairing token"}), 401

    session_token = secrets.token_urlsafe(48)
    SESSION_TOKENS.add(session_token)
    TOKENS_EXPIRY[session_token] = datetime.utcnow() + timedelta(hours=24)
    print("✅ New SESSION_TOKEN:", session_token)

    return jsonify({"session_token": session_token, "expires_in": 86400})


@app.route("/status", methods=["GET"])
@require_auth
def status():
    if SENTINEL_SERVICE:
        worker = SENTINEL_SERVICE.worker
        return jsonify(
            {
                "status": getattr(worker, "current_status", "Unknown"),
                "display_status": getattr(worker, "current_display", "Unknown"),
                "running": SENTINEL_SERVICE.thread.isRunning(),
            }
        )
    return jsonify({"status": "Service not ready"})


@app.route("/control/start", methods=["POST"])
@require_auth
def control_start():
    if SENTINEL_SERVICE:
        SENTINEL_SERVICE.remote_start()
        socketio.emit("status_update", {"running": True}, namespace="/events")
        return jsonify({"success": True})
    return jsonify({"error": "Service not available"}), 503


@app.route("/control/stop", methods=["POST"])
@require_auth
def control_stop():
    if SENTINEL_SERVICE:
        SENTINEL_SERVICE.remote_stop()
        socketio.emit("status_update", {"running": False}, namespace="/events")
        return jsonify({"success": True})
    return jsonify({"error": "Service not available"}), 503


@socketio.on("connect", namespace="/events")
def handle_connect():
    emit("connected", {"message": "Joined Sentinel events"})


def notify_scan_complete(threats: int):
    socketio.emit(
        "scan_complete",
        {"threats": threats, "timestamp": datetime.utcnow().isoformat()},
        namespace="/events",
    )


def notify_status_changed(status: str):
    socketio.emit("status_changed", {"status": status}, namespace="/events")


def notify_display_changed(display: str):
    socketio.emit("display_changed", {"display": display}, namespace="/events")


def run_server(host: str = None, port: int = None):
    if host is None:
        host = MY_IP
    if port is None:
        port = PAIR_PORT

    print(f"🚀 Sentinel remote server starting on https://{host}:{port}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_PATH), keyfile=str(KEY_PATH))

    socketio.run(
        app,
        host=host,
        port=port,
        ssl_context=ctx,
        debug=False,
    )


def start_remote_server(sentinel_service=None, host: str = None, port: int = None):
    global SENTINEL_SERVICE
    SENTINEL_SERVICE = sentinel_service
    t = threading.Thread(target=run_server, args=(host, port), daemon=True)
    t.start()
    return t
