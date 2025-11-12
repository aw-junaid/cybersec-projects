#!/usr/bin/env python3
"""
uploader_server.py - Safe Upload Server (lab only)
Requirements: pip install flask python-magic
Usage: python3 uploader_server.py --host 127.0.0.1 --port 8000 --token mylabtoken
Notes: By default binds to localhost. Allowed extensions: txt,jpg,png,safe.
Uploaded files are saved with a .safe suffix and 0600 permissions.
"""
import os, argparse, pathlib, logging, time, werkzeug
from flask import Flask, request, jsonify, abort
import magic  # python-magic for basic mime checks; optional but recommended
from werkzeug.utils import secure_filename

# Configuration
UPLOAD_DIR = "uploads"
ALLOWED_EXTS = {".txt", ".jpg", ".jpeg", ".png", ".safe"}
MAX_SIZE = 5 * 1024 * 1024   # 5 MB
DEFAULT_TOKEN = "lab-uploader-token"

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_SIZE

# Ensure upload dir exists
os.makedirs(UPLOAD_DIR, exist_ok=True)
logging.basicConfig(filename="uploader_server.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s: %(message)s")

def allowed_extension(filename):
    ext = pathlib.Path(filename).suffix.lower()
    return ext in ALLOWED_EXTS

def sanitize_and_store(fileobj, filename):
    # secure_filename will remove path traversal chars
    safe_name = secure_filename(filename)
    if not safe_name:
        safe_name = f"upload_{int(time.time())}"
    # append .safe to ensure non-executable on accidental transfer
    safe_name = safe_name + ".safe"
    dest = os.path.join(UPLOAD_DIR, safe_name)
    # Write atomically: write to temp then rename
    tmp = dest + ".tmp"
    with open(tmp, "wb") as f:
        while True:
            chunk = fileobj.read(8192)
            if not chunk:
                break
            f.write(chunk)
    # set safe permissions: rw------- (owner only), no exec
    os.chmod(tmp, 0o600)
    os.replace(tmp, dest)
    return dest

@app.route("/upload", methods=["POST"])
def upload():
    # Auth token via header or form field
    token = request.headers.get("X-UPLOAD-TOKEN") or request.form.get("token")
    if token != app.config['UPLOAD_TOKEN']:
        logging.warning("Unauthorized upload attempt from %s", request.remote_addr)
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if "file" not in request.files:
        return jsonify({"ok": False, "error": "no file part"}), 400

    file = request.files["file"]
    orig_name = file.filename or "unnamed"

    # basic extension check
    if not allowed_extension(orig_name):
        logging.info("Rejected extension from %s filename=%s", request.remote_addr, orig_name)
        return jsonify({"ok": False, "error": "disallowed extension"}), 400

    # optionally check mime sniff
    # read small head to check type then reset
    head = file.stream.read(2048)
    file.stream.seek(0)
    try:
        m = magic.from_buffer(head, mime=True)
    except Exception:
        m = "unknown"
    # You can whitelist mime types if desired. We'll log it.
    logging.info("Upload attempt from %s filename=%s mime=%s size_estimate=%d",
                 request.remote_addr, orig_name, m, request.content_length or 0)

    # store safely
    try:
        path = sanitize_and_store(file.stream, orig_name)
    except werkzeug.exceptions.RequestEntityTooLarge:
        return jsonify({"ok": False, "error": "file too large"}), 413
    except Exception as e:
        logging.exception("Storage error")
        return jsonify({"ok": False, "error": "storage failed"}), 500

    logging.info("Stored file=%s from %s", path, request.remote_addr)
    return jsonify({"ok": True, "stored": path}), 201

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--token", default=DEFAULT_TOKEN)
    args = p.parse_args()
    app.config['UPLOAD_TOKEN'] = args.token
    print(f"Starting safe uploader on {args.host}:{args.port} token='{args.token}' (keep secret)")
    app.run(host=args.host, port=args.port)

if __name__ == "__main__":
    main()
