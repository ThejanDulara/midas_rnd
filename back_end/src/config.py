import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    # --- JWT Settings ---
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ACCESS_COOKIE_NAME = "access_token_cookie"
    JWT_REFRESH_COOKIE_NAME = "refresh_token_cookie"
    JWT_COOKIE_SECURE = False if os.getenv("FLASK_ENV") == "development" else True
    JWT_COOKIE_SAMESITE = "Lax" if os.getenv("FLASK_ENV") == "development" else "None"
    JWT_COOKIE_CSRF_PROTECT = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7)  # increased lifetime
    JWT_ACCESS_CSRF_HEADER_NAME = "X-CSRF-TOKEN-ACCESS"
    JWT_REFRESH_CSRF_HEADER_NAME = "X-CSRF-TOKEN-REFRESH"
    JWT_ACCESS_CSRF_FIELD_NAME = "csrf_access_token"
    JWT_REFRESH_CSRF_FIELD_NAME = "csrf_refresh_token"

    # --- Application Config ---
    COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "localhost")
    FRONTEND_BASE = os.getenv("FRONTEND_BASE")

    # --- Database Config ---
    MYSQL_HOST = os.getenv("MYSQL_HOST")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_DB = os.getenv("MYSQL_DB")
    MYSQL_USER = os.getenv("MYSQL_USER")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")

    # --- SMTP Config ---
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")
