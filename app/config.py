"""Application configuration, sourced entirely from the environment.

Nothing secret is ever committed here -- see .env.example for the full list of
variables and README.md for how to generate them.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_int(name: str, default: int) -> int:
    """Read an integer setting, tolerating blank and malformed values.

    A blueprint field left empty in the Render dashboard is set to an empty
    string rather than left unset, so ``os.environ.get(name, "587")`` returns
    ``""`` and not the fallback. Passing that to int() raises at import time and
    the whole service fails to boot with an opaque traceback -- so fall back
    here instead of trusting the value.
    """
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _normalise_database_url(url: str) -> str:
    """Render hands out ``postgres://`` URLs; SQLAlchemy 2 wants an explicit driver."""
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


class Config:
    # --- Core -------------------------------------------------------------
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-me")
    IS_PRODUCTION = os.environ.get("FLASK_ENV", "development") == "production"

    # --- Database ---------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = _normalise_database_url(
        os.environ.get("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'local.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        # Render's free Postgres closes idle connections; recycle before it does.
        "pool_pre_ping": True,
        "pool_recycle": 280,
    }

    # --- Encryption of medical fields at rest -----------------------------
    # Comma-separated Fernet keys. The first is used for new writes; the rest
    # stay listed so previously written rows remain readable during rotation.
    FIELD_ENCRYPTION_KEYS = os.environ.get("FIELD_ENCRYPTION_KEYS", "")

    # --- Blind index ------------------------------------------------------
    # Keys the HMAC used to look up encrypted usernames and emails.
    # Once accounts exist this must never change, or every lookup value changes
    # with it and nobody can sign in.
    BLIND_INDEX_KEY = os.environ.get("BLIND_INDEX_KEY", "")

    # --- Password hashing (Argon2id) --------------------------------------
    # Comfortably above the OWASP floor of m=19456, t=2, p=1, while staying
    # inside Render's free 512 MB tier: each concurrent hash allocates
    # ARGON2_MEMORY_KIB in full, and the start command caps concurrency at 4,
    # so this reserves 128 MB worst case. Raise to 65536 on a larger instance.
    ARGON2_TIME_COST = _env_int("ARGON2_TIME_COST", 3)
    ARGON2_MEMORY_KIB = _env_int("ARGON2_MEMORY_KIB", 32768)
    ARGON2_PARALLELISM = _env_int("ARGON2_PARALLELISM", 1)

    # --- Session cookies --------------------------------------------------
    SESSION_COOKIE_NAME = "auraline_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = IS_PRODUCTION
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 14  # 14 days
    SESSION_REFRESH_EACH_REQUEST = False

    # --- CSRF -------------------------------------------------------------
    WTF_CSRF_TIME_LIMIT = None  # tied to session lifetime instead

    # --- Where tag requests are sent -------------------------------------
    # Optional. Without SMTP configured, requests are still stored in the
    # database and readable by the site host at /admin/tag-requests.
    CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "")
    SMTP_HOST = os.environ.get("SMTP_HOST", "")
    SMTP_PORT = _env_int("SMTP_PORT", 587)
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "")

    # --- Admin access -----------------------------------------------------
    # Which accounts may open /admin/... . Nothing here is tied to a device or
    # a network: an admin signs in with these credentials from anywhere, the
    # same as any other account.
    #
    # Comma-separated usernames. This is the one to set -- it matches what you
    # actually type at sign-in, and is checked case-insensitively.
    ADMIN_USERNAMES = os.environ.get("ADMIN_USERNAMES", "")

    # Comma-separated emails. Kept alongside the above so an existing
    # deployment does not lose admin access the moment this is deployed;
    # either match grants access. Prefer ADMIN_USERNAMES for new setups.
    ADMIN_EMAILS = os.environ.get("ADMIN_EMAILS", "")
