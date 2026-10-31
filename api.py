
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
            b"WebAppData",
            token.encode(),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret,
            check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            return None

        auth_date = int(data.get("auth_date", 0))

        if auth_date > time.time() + 60:
            return None

        if time.time() - auth_date > 86400:
            return None

        user = json.loads(data.get("user", "{}"))

        return user if user.get("id") else None

    except Exception:
        app.logger.exception("Telegram verification error")
        return None


def get_database_url():
    return os.getenv("DATABASE_URL")


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

    database_url = get_database_url()

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
                           daily_date, referral_points, wallet_address
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
            "referral_points": row[5],
            "wallet_address": row[6]
        })

    except Exception:
        app.logger.exception("Wallet database error")
        return jsonify({
            "error": "Database connection failed"
        }), 500


@app.route("/api/connect-wallet", methods=["POST", "OPTIONS"])
def connect_wallet():

    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(silent=True) or {}

    user = verify_telegram_data(body.get("initData"))

    if not user:
        return jsonify({
            "error": "Invalid Telegram verification"
        }), 401

    address = body.get("address")

    if not isinstance(address, str):
        return jsonify({
            "error": "Wallet address is required"
        }), 400

    address = address.strip()

    if not address or len(address) > 128:
        return jsonify({
            "error": "Invalid wallet address"
        }), 400

    database_url = get_database_url()

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
                    UPDATE public.users
                    SET wallet_address = %s,
                        wallet_connected_at = NOW()
                    WHERE user_id = %s
                    AND (
                        wallet_address IS NULL
                        OR wallet_address = %s
                    )
                    RETURNING wallet_address
                    """,
                    (address, user["id"], address)
                )

                updated = cur.fetchone()

                if not updated:
                    conn.rollback()

                    return jsonify({
                        "error": "This wallet is already linked to another account, or your account has a different wallet connected."
                    }), 409

        return jsonify({
            "success": True,
            "wallet_address": address,
            "message": "Wallet address saved. Ownership has not yet been independently verified."
        })

    except Exception:
        app.logger.exception("Connect wallet database error")
        return jsonify({
            "error": "Could not save wallet address"
        }), 500


@app.route("/api/disconnect-wallet", methods=["POST", "OPTIONS"])
def disconnect_wallet():

    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(silent=True) or {}

    user = verify_telegram_data(body.get("initData"))

    if not user:
        return jsonify({
            "error": "Invalid Telegram verification"
        }), 401

    database_url = get_database_url()

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
                    UPDATE public.users
                    SET wallet_address = NULL,
                        wallet_connected_at = NULL
                    WHERE user_id = %s
                    """,
                    (user["id"],)
                )

        return jsonify({
            "success": True,
            "message": "Wallet disconnected from BilbyCoin."
        })

    except Exception:
        app.logger.exception("Disconnect wallet database error")
        return jsonify({
            "error": "Could not disconnect wallet"
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )
