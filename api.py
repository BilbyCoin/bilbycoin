import os
import json
import time
import hmac
import hashlib
import sqlite3
from urllib.parse import parse_qsl
from flask import Flask, jsonify, request

app = Flask(__name__)
DB_FILE = "bilbycoin.db"


def get_db():
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    return db


def verify_telegram_data(init_data):
    token = os.getenv("BOT_TOKEN")
    if not token or not init_data:
        return None

    try:
        pairs = parse_qsl(init_data, keep_blank_values=True)
        data = dict(pairs)

        if len(data) != len(pairs):
            return None

        received_hash = data.pop("hash", None)
        if not received_hash:
            return None

        check_string = "\n".join(
            f"{key}={value}" for key, value in sorted(data.items())
        )

        secret = hmac.new(
            b"WebAppData", token.encode(), hashlib.sha256
        ).digest()

        calculated = hmac.new(
            secret, check_string.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated, received_hash):
            return None

        auth_date = int(data.get("auth_date", 0))
        if auth_date > time.time() + 60 or time.time() - auth_date > 86400:
            return None

        user = json.loads(data.get("user", "{}"))
        return user if user.get("id") else None

    except (ValueError, TypeError, json.JSONDecodeError):
        return None


@app.route("/")
def home():
    return "BilbyCoin API is running!"


@app.route("/api/wallet", methods=["POST"])
def wallet():
    body = request.get_json(silent=True) or {}
    user = verify_telegram_data(body.get("initData"))

    if not user:
        return jsonify({"error": "Invalid Telegram verification"}), 401

    with get_db() as db:
        account = db.execute(
            """
            SELECT user_id, username, balance,
                   daily_points, referral_points
            FROM users WHERE user_id = ?
            """,
            (user["id"],)
        ).fetchone()

    if account is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify(dict(account))


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
