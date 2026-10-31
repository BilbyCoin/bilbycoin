
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


@app.route("/api/claim-daily", methods=["POST", "OPTIONS"])
def claim_daily():

    if request.method == "OPTIONS":
        return "", 204

    body = request.get_json(silent=True) or {}
    user = verify_telegram_data(body.get("initData"))

    if not user:
        return jsonify({"error": "Invalid Telegram verification"}), 401

    database_url = get_database_url()
    if not database_url:
        return jsonify({"error": "Database not configured"}), 500

    try:
        with psycopg.connect(database_url, sslmode="require") as conn:
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
                    INSERT INTO public.daily_claims (user_id, claimed_at)
                    VALUES (%s, NOW())
                    ON CONFLICT (user_id) DO UPDATE
                    SET claimed_at = NOW()
                    WHERE public.daily_claims.claimed_at <= NOW() - INTERVAL '24 hours'
                    RETURNING claimed_at
                    """,
                    (user["id"],)
                )
                claim = cur.fetchone()

                if not claim:
                    cur.execute(
                        "SELECT claimed_at FROM public.daily_claims WHERE user_id = %s",
                        (user["id"],)
                    )
                    previous = cur.fetchone()
                    return jsonify({
                        "error": "You have already claimed your daily points. Please try again after 24 hours.",
                        "next_claim_at": (previous[0] + __import__("datetime").timedelta(hours=24)).isoformat() if previous else None
                    }), 429

                cur.execute(
                    """
                    UPDATE public.users
                    SET balance = COALESCE(balance, 0) + 100,
                        daily_points = COALESCE(daily_points, 0) + 100,
                        daily_date = CURRENT_DATE
                    WHERE user_id = %s
                    RETURNING balance, daily_points
                    """,
                    (user["id"],)
                )
                updated = cur.fetchone()

        return jsonify({
            "success": True,
            "points_awarded": 100,
            "balance": updated[0],
            "daily_points": updated[1],
            "message": "100 points added to your balance! Come back after 24 hours for your next claim."
        })

    except Exception:
        app.logger.exception("Daily claim database error")
        return jsonify({"error": "Daily claim is temporarily unavailable. Please try again later."}), 500


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


@app.route("/api/monetag-postback", methods=["GET"])
def monetag_postback():
    supplied_secret = request.args.get("secret", "")
    expected_secret = os.getenv("MONETAG_POSTBACK_SECRET", "")

    if not expected_secret or not supplied_secret or not hmac.compare_digest(supplied_secret, expected_secret):
        return "", 403

    ymid = request.args.get("ymid", "").strip()
    event_type = request.args.get("event_type", "").strip()
    reward_event_type = request.args.get("reward_event_type", "").strip()
    zone_id = request.args.get("zone_id", "").strip()
    telegram_id = request.args.get("telegram_id", "").strip()
    estimated_price = request.args.get("estimated_price", "0").strip()
    sub_zone_id = request.args.get("sub_zone_id", "").strip()

    # Only a paid impression can earn points. Clicks and unpaid events do not.
    if not ymid or len(ymid) > 200:
        return "", 400
    if event_type != "impression" or reward_event_type != "valued":
        return "", 200
    if not zone_id.isdigit() or not telegram_id.isdigit():
        return "", 200

    try:
        user_id = int(telegram_id)
        zone_number = int(zone_id)
        price = float(estimated_price)
        if user_id <= 0 or zone_number <= 0 or price < 0 or price > 1000:
            return "", 400
        sub_zone_number = int(sub_zone_id) if sub_zone_id.isdigit() else None
    except (TypeError, ValueError):
        return "", 400

    database_url = get_database_url()
    if not database_url:
        app.logger.error("Monetag postback received but DATABASE_URL is missing")
        return "", 500

    try:
        with psycopg.connect(database_url, sslmode="require") as conn:
            with conn.cursor() as cur:
                # Serialize reward checks per user so concurrent callbacks cannot
                # exceed the daily limit.
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (user_id,))

                cur.execute(
                    "SELECT 1 FROM public.users WHERE user_id = %s",
                    (user_id,)
                )
                if not cur.fetchone():
                    return "", 200

                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM public.monetag_events
                    WHERE user_id = %s
                      AND created_at >= date_trunc('day', NOW())
                    """,
                    (user_id,)
                )
                today_count = cur.fetchone()[0]
                if today_count >= 3:
                    return "", 200

                cur.execute(
                    """
                    INSERT INTO public.monetag_events
                        (ymid, user_id, zone_id, sub_zone_id, event_type,
                         reward_event_type, estimated_price, credited_points)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 50)
                    ON CONFLICT (ymid) DO NOTHING
                    RETURNING ymid
                    """,
                    (ymid, user_id, zone_number, sub_zone_number,
                     event_type, reward_event_type, price)
                )
                inserted = cur.fetchone()

                if inserted:
                    cur.execute(
                        """
                        UPDATE public.users
                        SET balance = COALESCE(balance, 0) + 50
                        WHERE user_id = %s
                        """,
                        (user_id,)
                    )

        return "", 200

    except Exception:
        app.logger.exception("Monetag postback processing failed")
        return "", 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )
