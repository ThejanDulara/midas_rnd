from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from src.db import init_db
from src.auth_routes import auth_bp
from src.user_routes import user_bp
from src.admin_routes import admin_bp
from src.public_routes import public_bp
from src.config import Config
import os


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # ---------- CORS (THIS MUST BE FIRST) ----------
    CORS(
        app,
        supports_credentials=True,
        origins=[
            "https://midasmedia.agency",
            "https://www.midasmedia.agency",
        ],
    )

    # ---------- JWT ----------
    app.config.update(
        JWT_TOKEN_LOCATION=["cookies"],
        JWT_COOKIE_DOMAIN=".midasmedia.agency",
        JWT_COOKIE_SECURE=True,
        JWT_COOKIE_SAMESITE="None",
        JWT_COOKIE_CSRF_PROTECT=False,
        JWT_ACCESS_COOKIE_PATH="/",
    )

    jwt = JWTManager(app)

    # ---------- JWT error handlers (CORS-safe now) ----------
    @jwt.unauthorized_loader
    def unauthorized_callback(reason):
        return {"error": "Missing or invalid JWT"}, 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {"error": "Invalid token"}, 422

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {"error": "Token expired"}, 401

    # ---------- DB + routes ----------
    init_db(app)
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(user_bp, url_prefix="/api/user")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(public_bp, url_prefix="/api/public")

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
