"""Lightweight JSON-based internationalization utility."""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict

from flask import current_app, request, g
from flask_login import current_user


_LOCALE_COOKIE = "gov_locale"


def _translations_dir() -> str:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "translations"))
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


@lru_cache(maxsize=8)
def _load(lang: str) -> Dict[str, str]:
    path = os.path.join(_translations_dir(), f"{lang}.json")
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except Exception:
            return {}


def translate(key: str, lang: str | None = None, default: str | None = None) -> str:
    locale = (lang or getattr(g, "locale", None) or "en").lower()
    bundle = _load(locale)
    if key in bundle:
        return bundle[key]
    if locale != "en":
        base = _load("en")
        if key in base:
            return base[key]
    return default or key


def supported_languages(app_config) -> list[str]:
    langs = (getattr(app_config, "SUPPORTED_LANGUAGES", "en,hi") or "en,hi").split(",")
    return [l.strip().lower() for l in langs if l.strip()]


def select_locale(app_config, user=None) -> str:
    langs = supported_languages(app_config)
    requested = request.args.get("lang") or request.cookies.get(_LOCALE_COOKIE)
    if user and getattr(user, "language_preference", None):
        requested = user.language_preference
    if requested and requested.lower() in langs:
        return requested.lower()
    return langs[0] if langs else "en"


def persist_user_locale(user, lang: str) -> None:
    if not user:
        return
    user.language_preference = lang


def inject_i18n(app):
    @app.before_request
    def _set_locale():
        g.locale = select_locale(app.config, current_user)

    @app.context_processor
    def _ctx():
        return {"_": lambda key, default=None: translate(key, getattr(g, "locale", None), default)}

    @app.after_request
    def _persist(response):
        lang = getattr(g, "locale", None) or "en"
        response.set_cookie(_LOCALE_COOKIE, lang, max_age=60 * 60 * 24 * 365, samesite="Lax", secure=app.config.get("SESSION_COOKIE_SECURE", True))
        return response

    return app
