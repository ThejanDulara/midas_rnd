from flask import Blueprint, request, jsonify, current_app as app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    set_access_cookies,
    unset_jwt_cookies,
    jwt_required,
    get_jwt_identity,
)
import pymysql
import datetime
from .config import Config
from .emailer import send_mail
from .otp import create_otp, verify_otp, mark_otp_used

auth_bp = Blueprint("auth", __name__)


def get_user_by_email(email):
    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
    )
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM user WHERE email=%s", (email,))
        user = cur.fetchone()
    conn.close()
    return user


# ================= SIGN IN =================
@auth_bp.post("/signin")
def signin():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    u = get_user_by_email(email)
    if not u or not check_password_hash(u["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    if not u["is_approved"]:
        return jsonify({"error": "Account pending approval"}), 403

    token = create_access_token(
        identity=str(u["id"]),
        additional_claims={
            "email": u["email"],
            "first_name": u["first_name"],
            "is_admin": u["is_admin"],
            "can_update_data": u["can_update_data"],
        },
    )

    resp = jsonify({
        "id": u["id"],
        "email": u["email"],
        "first_name": u["first_name"],
        "is_admin": u["is_admin"],
    })

    # ✅ SET COOKIE
    set_access_cookies(resp, token)
    return resp, 200


# ================= SIGN OUT =================
@auth_bp.post("/signout")
def signout():
    resp = jsonify({"message": "signed out"})
    unset_jwt_cookies(resp)
    return resp, 200


# ================= ME =================
@auth_bp.get("/me")
@jwt_required()
def me():
    user_id = get_jwt_identity()

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
    )

    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, first_name, last_name, email, designation,
                   is_admin, can_update_data, profile_pic
            FROM user WHERE id=%s
        """, (user_id,))
        user = cur.fetchone()

    conn.close()
    return jsonify(user), 200


# ================= FORGOT PASSWORD =================
@auth_bp.post("/forgot")
def forgot_password():
    email = request.get_json().get("email")
    user = get_user_by_email(email)

    if not user:
        return jsonify({"error": "No account found"}), 404

    otp_code = create_otp(user["id"])

    send_mail(
        email,
        "Midas Media – Password Reset OTP",
        f"Your OTP is {otp_code}. It expires in 10 minutes."
    )

    return jsonify({"message": "OTP sent"}), 200


# ================= RESET PASSWORD =================
@auth_bp.post("/reset")
def reset_password():
    data = request.get_json()
    email = data.get("email")
    otp = data.get("otp")
    new_password = data.get("new_password")

    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not verify_otp(user["id"], otp):
        return jsonify({"error": "Invalid or expired OTP"}), 400

    hashed_pw = generate_password_hash(new_password)

    conn = pymysql.connect(
        host=Config.MYSQL_HOST,
        port=int(Config.MYSQL_PORT),
        user=Config.MYSQL_USER,
        password=Config.MYSQL_PASSWORD,
        database=Config.MYSQL_DB,
        autocommit=True,
    )

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE user SET password_hash=%s WHERE email=%s",
            (hashed_pw, email)
        )

    conn.close()
    mark_otp_used(user["id"])
    return jsonify({"message": "Password updated"}), 200
