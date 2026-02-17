from flask import Flask, request
from flask_jwt_extended import JWTManager
from src.db import init_db
from src.auth_routes import auth_bp
from src.user_routes import user_bp
from src.admin_routes import admin_bp
from src.public_routes import public_bp
from src.config import Config
import os


def create_app():
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.from_object(Config)

    # ================= JWT CONFIG =================
    app.config.update(
        JWT_TOKEN_LOCATION=["cookies"],
        JWT_COOKIE_DOMAIN=".midasmedia.agency",   # ✅ SHARE ACROSS ALL SUBDOMAINS
        JWT_COOKIE_SECURE=True,                   # ✅ HTTPS ONLY
        JWT_COOKIE_SAMESITE="None",               # ✅ CROSS-SITE COOKIE
        JWT_COOKIE_CSRF_PROTECT=False,
        JWT_ACCESS_COOKIE_PATH="/",
    )

    jwt = JWTManager(app)

    # ================= PRE-FLIGHT HANDLER =================
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            resp = app.make_response("")
            origin = request.headers.get("Origin")

            if origin and origin.endswith(".midasmedia.agency"):
                resp.headers["Access-Control-Allow-Origin"] = origin

            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            return resp

    # ================= GLOBAL CORS HEADERS =================
    @app.after_request
    def add_cors_headers(response):
        origin = request.headers.get("Origin")

        if origin and origin.endswith(".midasmedia.agency"):
            response.headers["Access-Control-Allow-Origin"] = origin

        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return response

    # ================= JWT ERROR HANDLERS =================
    @jwt.unauthorized_loader
    def unauthorized_callback(reason):
        return {"error": "Missing or invalid JWT"}, 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {"error": "Invalid JWT"}, 422

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {"error": "Token expired"}, 401

    # ================= INIT DB + ROUTES =================
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
