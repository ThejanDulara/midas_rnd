import pymysql
from flask import g

def _connect(app):
    return pymysql.connect(
        host=app.config["MYSQL_HOST"],
        port=app.config["MYSQL_PORT"],
        user=app.config["MYSQL_USER"],
        password=app.config["MYSQL_PASSWORD"],
        database=app.config["MYSQL_DB"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )

def init_db(app):
    @app.before_request
    def before_request():
        g.db = _connect(app)

    @app.teardown_request
    def teardown_request(exception):
        db = getattr(g, "db", None)
        if db:
            db.close()
