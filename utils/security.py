"""Security helpers for headers, input sanitation, and auth utilities."""
import hashlib
import html
import secrets
from typing import Mapping
from urllib.parse import urlparse, urljoin

from flask import request


def sanitize_input(data: Mapping) -> dict:
    """Return a sanitized copy of incoming data to reduce injection risk."""
    sanitized = {}
    for key, value in data.items():
        sanitized[html.escape(str(key))] = html.escape(str(value))
    return sanitized


def apply_security_headers(response, force_https: bool = False):
    """Apply security headers suitable for production deployments while allowing needed capabilities."""
    csp = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src-elem 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://maps.googleapis.com; "
        "script-src-elem 'self' https://cdn.jsdelivr.net https://unpkg.com https://maps.googleapis.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "img-src 'self' data: blob: https://maps.gstatic.com https://cdn.jsdelivr.net https://unpkg.com https://*; "
        "connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://tile.openstreetmap.org https://*.tile.openstreetmap.org https://nominatim.openstreetmap.org; "
        "frame-src 'self' https://www.google.com; "
        "worker-src 'self' blob:;"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    # Allow geolocation while keeping other sensors disabled
    response.headers.setdefault("Permissions-Policy", "geolocation=(self), microphone=(), camera=()")
    if force_https or request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    return response


def is_safe_redirect_url(target: str) -> bool:
    """Validate redirect targets to prevent open redirect attacks."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def generate_otp(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def password_meets_policy(password: str) -> tuple[bool, str | None]:
    """Enforce a sane password baseline for production."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if password.lower() == password or password.upper() == password:
        return False, "Use a mix of upper and lower case characters."
    if not any(c.isdigit() for c in password):
        return False, "Include at least one digit."
    if not any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password):
        return False, "Include at least one symbol."
    return True, None


# Simple rate-limit ready structure (hook up to cache/store later)
_attempts = {}


def track_attempt(key: str, limit: int = 10):
    """Track attempts by key (e.g., IP or email) to enable rate limiting."""
    count = _attempts.get(key, 0) + 1
    _attempts[key] = count
    return count <= limit
