"""Flask application factory for a production-ready government-grade service foundation."""
import os
import uuid
from typing import Optional
from flask import Flask, render_template, request, g
from flask_login import current_user
from sqlalchemy import create_engine, text
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
from utils.logger import init_logging
from utils.security import apply_security_headers, sanitize_input
from utils.i18n import inject_i18n, supported_languages
from utils.alert_engine import alerts_for_user
from utils.identity_linker import active_entity_context
from extensions import csrf, db, migrate, login_manager


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(403)
    def forbidden(error):
        app.logger.warning("403 Forbidden", extra={"path": request.path, "method": request.method})
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.warning("404 Not Found", extra={"path": request.path, "method": request.method})
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception("500 Internal Server Error")
        return render_template("errors/500.html"), 500


def ensure_default_roles_and_admin(app: Flask) -> None:
    """Ensure baseline roles exist and a default admin can log in without registering."""
    from models import Role, User  # Local import to avoid circular dependency

    default_roles = [
        ("Citizen", "Default role for citizens"),
        ("Government Officer", "Role for verified government officers"),
        ("Contractor", "Role for registered contractors"),
        ("Admin", "Platform administrator with full privileges"),
    ]

    role_cache: dict[str, Role] = {}
    for name, description in default_roles:
        role_cache[name] = Role.get_or_create(name, description=description)

    admin_email = (app.config.get("DEFAULT_ADMIN_EMAIL") or "").lower().strip()
    admin_password = app.config.get("DEFAULT_ADMIN_PASSWORD") or ""
    if not admin_email or not admin_password:
        return

    admin_role = role_cache.get("Admin") or Role.get_or_create("Admin", description="Platform administrator")
    admin_user = User.query.filter_by(email=admin_email).first()

    if admin_user:
        updates = False
        if admin_user.role != admin_role:
            admin_user.role = admin_role
            updates = True
        if not admin_user.is_active:
            admin_user.is_active = True
            updates = True
        if not admin_user.is_email_verified:
            admin_user.is_email_verified = True
            updates = True
        if updates:
            db.session.add(admin_user)
            db.session.commit()
        return

    admin_user = User(
        full_name="System Administrator",
        email=admin_email,
        role=admin_role,
        is_email_verified=True,
        is_active=True,
    )
    admin_user.set_password(admin_password)
    db.session.add(admin_user)
    db.session.commit()


def ensure_database_exists(database_uri: str) -> None:
    """Create the target database if it does not exist (PostgreSQL + SQLite support)."""
    url = make_url(database_uri)

    if url.drivername.startswith("sqlite"):
        # For SQLite just make sure the parent directory exists.
        if url.database:
            os.makedirs(os.path.dirname(url.database) or ".", exist_ok=True)
        return

    if url.drivername.startswith("postgres"):
        db_name = url.database
        admin_url = url.set(database=os.getenv("POSTGRES_DB_ADMIN", "postgres"))
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as conn:
                exists = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": db_name}
                ).scalar()
                if not exists:
                    conn.execute(text(f'CREATE DATABASE "{db_name}"'))
        except OperationalError:
            # If we cannot connect/create, let the normal app startup fail loudly later.
            pass
        finally:
            engine.dispose()



def create_app(config_name: Optional[str] = None) -> Flask:
    """Application factory with environment-aware configuration."""
    load_dotenv()

    app = Flask(__name__, instance_relative_config=True)

    # Resolve configuration
    from config import DevelopmentConfig, ProductionConfig

    config_key = (config_name or os.getenv("FLASK_CONFIG") or os.getenv("FLASK_ENV") or "production").lower()
    config_map = {
        "development": DevelopmentConfig,
        "dev": DevelopmentConfig,
        "production": ProductionConfig,
        "prod": ProductionConfig,
    }
    config_class = config_map.get(config_key, ProductionConfig)
    app.config.from_object(config_class())

    ensure_database_exists(app.config["SQLALCHEMY_DATABASE_URI"])

    # Optional instance-specific overrides
    app.config.from_pyfile("config.py", silent=True)
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config.get("COMPLAINT_UPLOAD_FOLDER", os.path.join(app.instance_path, "complaint_uploads")), exist_ok=True)
    os.makedirs(app.config.get("PROJECT_SNAPSHOT_DIR", os.path.join(app.instance_path, "project_snapshots")), exist_ok=True)
    os.makedirs(app.config.get("RTI_REPORT_DIR", os.path.join(app.instance_path, "rti_reports")), exist_ok=True)

    # Initialize logging early
    logger = init_logging(app)
    app.logger = logger

    # Initialize extensions
    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        from models import User  # Local import to avoid circular dependency

        if not user_id:
            return None
        # IDs are stored as string UUIDs in SQLite; avoid casting to UUID to prevent driver errors.
        return User.query.get(str(user_id))

    # Blueprints
    from routes import main_bp, auth_bp, project_bp, complaints_bp, transparency_bp
    from utils.follow_up_agent import run_follow_up_cycle

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(project_bp)
    app.register_blueprint(complaints_bp)
    app.register_blueprint(transparency_bp)

    @app.route("/favicon.ico")
    def favicon():
        """Serve a favicon if present; otherwise return an empty response to avoid 404 noise."""
        static_ico = os.path.join(app.static_folder or "static", "favicon.ico")
        if os.path.exists(static_ico):
            return app.send_static_file("favicon.ico")
        return "", 204

    @app.cli.command("followup-run")
    def followup_run():
        """Execute automated complaint follow-ups (schedule this via cron)."""
        run_follow_up_cycle(app)

    # Error handlers
    register_error_handlers(app)

    # i18n and context globals
    inject_i18n(app)

    @app.context_processor
    def inject_global_context():
        alerts = []
        try:
            if current_user and current_user.is_authenticated:
                alerts = alerts_for_user(current_user)
        except Exception:
            alerts = []
        try:
            entity_ctx = active_entity_context(current_user)
        except Exception:
            entity_ctx = None
        return {
            "active_alerts": alerts,
            "active_alert_count": len(alerts),
            "supported_languages": supported_languages(app.config),
            "linked_entity_context": entity_ctx,
        }

    # Request lifecycle hooks
    @app.before_request
    def _before_request() -> None:
        g.sanitized_args = sanitize_input(request.args)
        g.sanitized_form = sanitize_input(request.form)

    @app.after_request
    def _after_request(response):
        return apply_security_headers(response, force_https=app.config.get("PREFERRED_URL_SCHEME") == "https")

    # Ensure tables exist so first run creates the database structure automatically.
    with app.app_context():
        db.create_all()
        ensure_default_roles_and_admin(app)

    return app


# Expose the Flask application for WSGI servers (e.g., gunicorn app:app).
app = create_app()


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, use_reloader=False)
