from flask import Flask, jsonify, request

from integration.pipeline import ShieldMailPipeline
from integration.gmail_oauth import gmail_oauth

app = Flask(__name__)

import os

app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,  # Local HTTP development only
)

app.register_blueprint(gmail_oauth)

pipeline = ShieldMailPipeline()


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "ShieldMail",
    })


@app.post("/scan")
def scan_email():
    if "file" not in request.files:
        return jsonify({
            "error": "No email file provided"
        }), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({
            "error": "No filename provided"
        }), 400

    if not file.filename.lower().endswith(".eml"):
        return jsonify({
            "error": "Only .eml files are supported"
        }), 400

    raw_bytes = file.read()

    if not raw_bytes:
        return jsonify({
            "error": "Empty email file"
        }), 400

    try:
        result = pipeline.analyze(raw_bytes)

        return jsonify({
            "status": "analyzed",
            "filename": file.filename,
            "result": result,
        })

    except Exception as exc:
        return jsonify({
            "error": "Email analysis failed",
            "details": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(debug=True)