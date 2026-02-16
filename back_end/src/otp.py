from datetime import datetime, timedelta
import random
from flask import g

def create_otp(user_id, minutes=10):
    code = str(random.randint(100000, 999999))
    expires = datetime.utcnow() + timedelta(minutes=minutes)
    with g.db.cursor() as cur:
        cur.execute("INSERT INTO password_reset_otp (user_id, otp_code, expires_at) VALUES (%s,%s,%s)",
                    (user_id, code, expires))
    return code

def verify_otp(user_id, code):
    with g.db.cursor() as cur:
        cur.execute("""SELECT id, expires_at, used FROM password_reset_otp
                       WHERE user_id=%s AND otp_code=%s
                       ORDER BY id DESC LIMIT 1""", (user_id, code))
        row = cur.fetchone()
    if not row or row["used"] or row["expires_at"] < datetime.utcnow():
        return None
    return row["id"]

def mark_otp_used(otp_id):
    with g.db.cursor() as cur:
        cur.execute("UPDATE password_reset_otp SET used=1 WHERE id=%s", (otp_id,))
