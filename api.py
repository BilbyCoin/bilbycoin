
import os
import json
import hmac
import hashlib
import time
from urllib.parse import parse_qsl

import psycopg
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Max-Age"] = "86400"
    return response


def verify_telegram_data(init_data):
    token = os.getenv("BOT_TOKEN")

    if not token or not init_data:
        return None

    try:
        pairs = parse_qsl(init_data, keep_blank_values=True)

        if len(dict(pairs)) != len(pairs):
            return None

        data = dict(pairs)
        received_hash = data.pop("hash", None)

        if not received_hash:
            return None

        check_string = "\n".join(
            f"{key}={value}" for key, value in sorted(data.items())
        )

        secret = hmac.new(
            b"WebAppData", token.encode(), hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret, check_string.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            return None

        auth_date = int(data.get("auth_date", 0))

        if time.time() - auth_date > 86400:
            return None

        if auth_date > time.time() + 60:
            return None

        return json.loads(data["user"])

    except Exception:
        app.logger.exception("Telegram verification error")
        return None


@app.route("/")
def home():
    return "BilbyCoin API is running!"


@app.route("/api/wallet", methods=["POST", "OPTIONS"])
def wallet():

    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(silent=True) or {}

    user = verify_telegram_data(body.get("initData"))

    if not user:
        return jsonify({
            "error": "Invalid Telegram verification"
        }), 401

    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        return jsonify({
            "error": "Database not configured"
        }), 500

    try:
        with psycopg.connect(
            database_url,
            sslmode="require"
        ) as conn:

            with conn.cursor() as cur:

                cur.execute(
                    """
                    INSERT INTO public.users (user_id, username)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id) DO NOTHING
                    """,
                    (user["id"], user.get("username"))
                )

                cur.execute(
                    """
                    SELECT user_id, username, balance, daily_points,
                           daily_date, referral_points
                    FROM public.users
                    WHERE user_id = %s
                    """,
                    (user["id"],)
                )

                row = cur.fetchone()

        if not row:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "user_id": row[0],
            "username": row[1],
            "balance": row[2],
            "daily_points": row[3],
            "daily_date": str(row[4]) if row[4] else None,
            "referral_points": row[5]
        })

    except Exception:
        app.logger.exception("Wallet database error")
        return jsonify({
            "error": "Database connection failed"
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )
