"""Environment-aware configuration for the Flask application."""
import os
from datetime import timedelta


class BaseConfig:
    def __init__(self) -> None:
        # Defaults for local dev: SQLite db and a non-empty secret. Override via env for production.
        self.SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
        db_url = os.getenv("DATABASE_URL")
        # If DATABASE_URL points to a placeholder host (e.g., db_host) or is missing, fall back to SQLite for local dev.
        if db_url and "db_host" not in db_url:
            self.SQLALCHEMY_DATABASE_URI = db_url
        else:
            self.SQLALCHEMY_DATABASE_URI = os.getenv(
                "SQLITE_URL",
                f"sqlite:///{os.path.join(os.getcwd(), 'instance', 'app.db')}",
            )
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_size": int(os.getenv("DB_POOL_SIZE", 10)),
            "max_overflow": int(os.getenv("DB_MAX_OVERFLOW", 20)),
            "pool_timeout": int(os.getenv("DB_POOL_TIMEOUT", 30)),
            "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", 1800)),
        }
        self.SESSION_COOKIE_HTTPONLY = True
        self.REMEMBER_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.PERMANENT_SESSION_LIFETIME = timedelta(days=365)
        self.REMEMBER_COOKIE_DURATION = timedelta(days=365)
        self.PREFERRED_URL_SCHEME = os.getenv("PREFERRED_URL_SCHEME", "https")
        self.WTF_CSRF_TIME_LIMIT = 3600
        self.WTF_CSRF_ENABLED = True
        self.MAIL_SERVER = os.getenv("MAIL_SERVER", "")
        self.MAIL_PORT = int(os.getenv("MAIL_PORT", 25))
        self.MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
        self.MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
        self.MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
        self.MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
        self.MAIL_MONITOR_ADDRESS = os.getenv("MAIL_MONITOR_ADDRESS", "")
        self.MAIL_HIGHER_AUTHORITY = os.getenv("MAIL_HIGHER_AUTHORITY", "")
        self.GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
        self.GEMINI_VISION_MODEL = os.getenv("GEMINI_VISION_MODEL", "gemini-2.5-flash")
        self.LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
        self.LOG_DIR = os.getenv("LOG_DIR", os.path.join(os.getcwd(), "logs"))
        # Default to a valid public-domain-like address to satisfy email validators in prod
        self.DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@gov.in")
        self.DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@12345!")
        self.COMPLAINT_UPLOAD_FOLDER = os.getenv(
            "COMPLAINT_UPLOAD_FOLDER",
            os.path.join(os.getcwd(), "instance", "complaint_uploads"),
        )
        self.PROJECT_SNAPSHOT_DIR = os.getenv(
            "PROJECT_SNAPSHOT_DIR",
            os.path.join(os.getcwd(), "instance", "project_snapshots"),
        )
        self.RTI_REPORT_DIR = os.getenv(
            "RTI_REPORT_DIR",
            os.path.join(os.getcwd(), "instance", "rti_reports"),
        )
        self.MAX_IMAGE_UPLOAD_BYTES = int(os.getenv("MAX_IMAGE_UPLOAD_BYTES", 8 * 1024 * 1024))
        self.MAX_CONTENT_LENGTH = int(os.getenv("MAX_REQUEST_BYTES", 16 * 1024 * 1024))
        self.FOLLOW_UP_FIRST_AFTER_DAYS = int(os.getenv("FOLLOW_UP_FIRST_AFTER_DAYS", 2))
        self.FOLLOW_UP_INTERVAL_DAYS = int(os.getenv("FOLLOW_UP_INTERVAL_DAYS", 3))
        self.FOLLOW_UP_MAX_REMINDERS = int(os.getenv("FOLLOW_UP_MAX_REMINDERS", 3))
        self.ANALYTICS_CACHE_MINUTES = int(os.getenv("ANALYTICS_CACHE_MINUTES", 30))
        self.PUBLIC_HOME_CACHE_SECONDS = int(os.getenv("PUBLIC_HOME_CACHE_SECONDS", 120))
        self.CORRUPTION_THRESHOLDS = {
            "repeat_complaints_per_contractor": int(os.getenv("REPEAT_COMPLAINTS_PER_CONTRACTOR", 3)),
            "cost_overrun_pct": float(os.getenv("COST_OVERRUN_THRESHOLD_PCT", 15)),
            "delay_days": int(os.getenv("DELAY_THRESHOLD_DAYS", 30)),
            "repeat_complaints_per_location": int(os.getenv("REPEAT_COMPLAINTS_PER_LOCATION", 4)),
            "unresolved_complaints": int(os.getenv("UNRESOLVED_COMPLAINT_THRESHOLD", 5)),
        }
        self.RISK_SCORE_ALERT_THRESHOLD = int(os.getenv("RISK_SCORE_ALERT_THRESHOLD", 70))
        self.ALERT_DEDUP_HOURS = int(os.getenv("ALERT_DEDUP_HOURS", 24))
        self.SUPPORTED_LANGUAGES = os.getenv("SUPPORTED_LANGUAGES", "en,hi")
        self.OFFLINE_MAX_BATCH = int(os.getenv("OFFLINE_MAX_BATCH", 20))
        self.TIMELAPSE_MAX_IMAGES = int(os.getenv("TIMELAPSE_MAX_IMAGES", 120))


class DevelopmentConfig(BaseConfig):
    def __init__(self) -> None:
        super().__init__()
        self.DEBUG = True
        self.ENV = "development"
        self.SESSION_COOKIE_SECURE = False
        self.REMEMBER_COOKIE_SECURE = False


class ProductionConfig(BaseConfig):
    def __init__(self) -> None:
        super().__init__()
        self.DEBUG = False
        self.ENV = "production"
        self.SESSION_COOKIE_SECURE = True
        self.REMEMBER_COOKIE_SECURE = True
        self.PERMANENT_SESSION_LIFETIME = timedelta(days=365)
        # Only enable X-Sendfile when explicitly configured (e.g., behind nginx/apache that supports it)
        self.USE_X_SENDFILE = os.getenv("USE_X_SENDFILE", "false").lower() == "true"
        self.SEND_FILE_MAX_AGE_DEFAULT = 31536000
