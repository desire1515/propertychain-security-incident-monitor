from flask import Flask, request

from config import Config
from backend.routes.health import health_bp
from backend.routes.auth import auth_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.detection_rules import detection_rules_bp
from backend.routes.events import events_bp
from backend.routes.incidents import incidents_bp
from backend.routes.monitoring_sources import monitoring_sources_bp
from backend.routes.simulations import simulations_bp
from backend.routes.reports import reports_bp
from backend.routes.settings import settings_bp
from database.db import initialize_database
from backend.utils.security import get_csrf_token


def _build_app(test_config=None, initialize_db=True):
    app = Flask(__name__)
    app.config.from_object(Config)

    if test_config is not None:
        app.config.update(test_config)

    if initialize_db and not app.config.get("SECRET_KEY"):
        raise RuntimeError("PCSIRM_SECRET_KEY is missing from the environment.")

    app.extensions["database_initialized"] = False

    if initialize_db:
        with app.app_context():
            initialize_database()
        app.extensions["database_initialized"] = True

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(detection_rules_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(monitoring_sources_bp)
    app.register_blueprint(simulations_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)

    @app.before_request
    def initialize_database_on_first_request():
        if not app.config.get("SECRET_KEY") and not app.config.get("TESTING"):
            raise RuntimeError("PCSIRM_SECRET_KEY is missing from the environment.")

        if not app.extensions["database_initialized"]:
            with app.app_context():
                initialize_database()
            app.extensions["database_initialized"] = True

    @app.before_request
    def initialize_csrf_token():
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            get_csrf_token()

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self';",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response

    @app.route("/")
    def home():
        return {
            "application": "PCSIRM",
            "message": "PropertyChain Security Incident Response and Monitoring is running."
        }

    return app


def create_app(test_config=None):
    return _build_app(test_config)


app = _build_app(initialize_db=False)


if __name__ == "__main__":
    app.run(debug=False)
