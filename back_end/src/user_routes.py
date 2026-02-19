from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
import os, datetime
from flask import current_app as app

user_bp = Blueprint("user", __name__)

@user_bp.get("/profile")
@jwt_required()
def get_profile():
    ident = get_jwt_identity()
    with g.db.cursor() as cur:
        cur.execute("""SELECT id, first_name, last_name, email, designation, is_admin, profile_pic
                       FROM user WHERE id=%s""", (ident,))
        u = cur.fetchone()
    return jsonify(u), 200


@user_bp.post("/profile")
@jwt_required()
def update_profile():
    ident = get_jwt_identity()
    data = request.get_json()
    with g.db.cursor() as cur:
        cur.execute("""UPDATE user 
                       SET first_name=%s, last_name=%s, designation=%s 
                       WHERE id=%s""",
                    (data.get("first_name"), data.get("last_name"), data.get("designation"), ident))
    return jsonify({"message":"Profile updated"}), 200


from werkzeug.utils import secure_filename

@user_bp.post("/profile-picture")
@jwt_required()
def update_picture():
    user_id = get_jwt_identity()
    file = request.files.get("profile_pic")
    if not file:
        return jsonify({"error": "profile_pic file required"}), 400

    # Determine save directory
    # 1. Use UPLOAD_FOLDER from config if set
    # 2. Fallback to app.static_folder/uploads
    upload_dir = app.config.get("UPLOAD_FOLDER")
    if not upload_dir:
        upload_dir = os.path.join(app.static_folder, "uploads")
    
    os.makedirs(upload_dir, exist_ok=True)

    # Secure filename and add timestamp
    original_filename = secure_filename(file.filename)
    fname = f'{int(datetime.datetime.utcnow().timestamp())}_{original_filename}'
    save_path = os.path.join(upload_dir, fname)
    
    try:
        file.save(save_path)
    except Exception as e:
        print(f"❌ Upload Error: {str(e)}")
        return jsonify({"error": "Failed to save file"}), 500

    # Path for DB and frontend
    pic_path = f"/static/uploads/{fname}"

    # Update DB
    with g.db.cursor() as cur:
        cur.execute("UPDATE user SET profile_pic=%s WHERE id=%s", (pic_path, user_id))

    return jsonify({"profile_pic": pic_path}), 200



@user_bp.post("/change-password")
@jwt_required()
def change_password():
    ident = get_jwt_identity()   # 👈 this is the user_id as string
    data = request.get_json()
    old_p = data.get("old_password")
    new_p = data.get("new_password")
    confirm_p = data.get("confirm_password")

    if not old_p or not new_p or not confirm_p:
        return jsonify({"error": "All password fields required"}), 400
    if new_p != confirm_p:
        return jsonify({"error": "New passwords do not match"}), 400
    if len(new_p) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    with g.db.cursor() as cur:
        cur.execute("SELECT password_hash FROM user WHERE id=%s", (ident,))
        row = cur.fetchone()

    if not row or not check_password_hash(row["password_hash"], old_p):
        return jsonify({"error": "Old password incorrect"}), 400

    with g.db.cursor() as cur:
        cur.execute(
            "UPDATE user SET password_hash=%s WHERE id=%s",
            (generate_password_hash(new_p), ident),
        )

    return jsonify({"message": "Password changed"}), 200

