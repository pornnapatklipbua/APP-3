"""Security primitives: password hashing, at-rest field encryption, blind
indexes, rate limiting, auth guards and response hardening.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import re
import secrets
import time
import unicodedata
from collections import defaultdict, deque
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
)
from markupsafe import Markup, escape
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from .common_passwords import is_common

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
# Argon2id: the Password Hashing Competition winner, and what OWASP recommends
# first. Unlike bcrypt it is memory-hard, so an attacker with a GPU or ASIC farm
# cannot trade silicon for speed nearly as effectively.
#
# Defaults sit above the OWASP floor (32 MiB, t=3, p=1) while staying inside
# Render's free 512 MB tier: each concurrent hash allocates ARGON2_MEMORY_KIB in
# full, and the start command caps concurrency at 4. Raise it on a larger
# instance -- 65536 (64 MiB) is a good target when you have the headroom.

_HASHER_CACHE: dict[tuple, PasswordHasher] = {}

MIN_PASSWORD_LENGTH = 12
# Argon2 is memory-hard by design, so an unbounded password is a denial-of-service
# vector. NIST requires accepting at least 64; 128 is generous and still bounded.
MAX_PASSWORD_LENGTH = 128


def _hasher() -> PasswordHasher:
    cfg = current_app.config
    params = (
        cfg.get("ARGON2_TIME_COST", 3),
        cfg.get("ARGON2_MEMORY_KIB", 32768),
        cfg.get("ARGON2_PARALLELISM", 1),
    )
    cached = _HASHER_CACHE.get(params)
    if cached is None:
        cached = PasswordHasher(
            time_cost=params[0],
            memory_cost=params[1],
            parallelism=params[2],
            hash_len=32,
            salt_len=16,
        )
        _HASHER_CACHE[params] = cached
    return cached


def normalise_password(password: str) -> str:
    """NFKC-normalise so a password typed on a different keyboard or IME still
    matches. NIST SP 800-63B requires this for non-ASCII passwords."""
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    return _hasher().hash(normalise_password(password))


def verify_password(stored_hash: str | None, password: str) -> tuple[bool, str | None]:
    """Check a password. Returns ``(is_valid, replacement_hash_or_None)``.

    A replacement hash is returned when the stored hash used weaker parameters
    than the current settings, so callers can transparently upgrade it.

    When ``stored_hash`` is None (no such user), a verification is still
    performed against a dummy hash. Skipping it would make a missing account
    measurably faster to reject, which is how username enumeration is done.
    """
    hasher = _hasher()
    candidate = normalise_password(password)

    if not stored_hash:
        try:
            hasher.verify(_dummy_hash(), candidate)
        except Exception:
            pass
        return False, None

    try:
        hasher.verify(stored_hash, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False, None

    replacement = None
    try:
        if hasher.check_needs_rehash(stored_hash):
            replacement = hasher.hash(candidate)
    except Exception:  # pragma: no cover - never block a valid sign-in
        current_app.logger.warning("Could not evaluate password rehash.", exc_info=True)
    return True, replacement


_DUMMY_HASH_CACHE: dict[tuple, str] = {}


def _dummy_hash() -> str:
    cfg = current_app.config
    params = (
        cfg.get("ARGON2_TIME_COST", 3),
        cfg.get("ARGON2_MEMORY_KIB", 32768),
        cfg.get("ARGON2_PARALLELISM", 1),
    )
    cached = _DUMMY_HASH_CACHE.get(params)
    if cached is None:
        cached = _hasher().hash("timing-equalisation-placeholder")
        _DUMMY_HASH_CACHE[params] = cached
    return cached


def password_problems(password: str, username: str = "", email: str = "") -> list[str]:
    """Return every reason a password is unacceptable, or an empty list.

    Follows NIST SP 800-63B: length and a blocklist of known-weak values, with
    no composition rules. Mandatory symbol/digit/case requirements measurably
    push people towards 'Password1!' and add little real entropy.
    """
    problems: list[str] = []
    candidate = normalise_password(password)

    if len(candidate) < MIN_PASSWORD_LENGTH:
        problems.append(
            f"Use at least {MIN_PASSWORD_LENGTH} characters. "
            "A short phrase you can remember beats a short jumble you cannot."
        )
    if len(candidate) > MAX_PASSWORD_LENGTH:
        problems.append(f"Keep it under {MAX_PASSWORD_LENGTH} characters.")
    if is_common(candidate):
        problems.append("That password appears in lists of the most commonly used passwords.")
    if username and len(username) > 2 and username.casefold() in candidate.casefold():
        problems.append("Your password should not contain your username.")
    if email:
        local_part = email.split("@")[0]
        if len(local_part) > 2 and local_part.casefold() in candidate.casefold():
            problems.append("Your password should not contain your email address.")
    if candidate and len(set(candidate)) < 5:
        problems.append("That password repeats too few distinct characters.")

    return problems


# ---------------------------------------------------------------------------
# Field-level encryption
# ---------------------------------------------------------------------------
# Medical detail is the most sensitive thing this site holds, and on a site
# about epilepsy even a username is a health inference. Both are encrypted
# individually, so a database dump -- a backup file, a leaked connection string,
# a support engineer with read access -- is not a disclosure about anyone.

_FERNET_CACHE: dict[str, MultiFernet] = {}


def _get_fernet() -> MultiFernet:
    raw = current_app.config.get("FIELD_ENCRYPTION_KEYS", "") or ""
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        raise RuntimeError(
            "FIELD_ENCRYPTION_KEYS is not set. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; "
            'print(Fernet.generate_key().decode())"'
        )
    cache_key = ",".join(keys)
    cached = _FERNET_CACHE.get(cache_key)
    if cached is None:
        cached = MultiFernet([Fernet(k.encode()) for k in keys])
        _FERNET_CACHE[cache_key] = cached
    return cached


class EncryptedText(TypeDecorator):
    """Transparently encrypts a text column with Fernet (AES-128-CBC + HMAC).

    The first key in FIELD_ENCRYPTION_KEYS encrypts new writes; every key in the
    list is tried on read, so keys can be rotated by prepending a new one.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        text = str(value)
        if not text.strip():
            return None
        return _get_fernet().encrypt(text.encode("utf-8")).decode("ascii")

    def process_result_value(self, value: Any, dialect: Any) -> str | None:
        if value is None:
            return None
        try:
            return _get_fernet().decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeDecodeError):
            # A row we cannot decrypt (wrong/rotated-away key) must not take the
            # page down -- surface it as missing rather than as a 500.
            current_app.logger.error("Could not decrypt an encrypted column value.")
            return None


# ---------------------------------------------------------------------------
# Blind index
# ---------------------------------------------------------------------------
# Encrypted columns cannot be searched: Fernet output is randomised, so the same
# username encrypts differently every time. To still look someone up at sign-in,
# we store a keyed HMAC of the casefolded value alongside the ciphertext and
# query on that. Keyed, so an attacker holding the database cannot simply
# hash a guessed username and look for a match.
#
# BLIND_INDEX_KEY must never change once accounts exist -- every lookup value
# would change with it and nobody could sign in.


def blind_index(value: str) -> str:
    key = (current_app.config.get("BLIND_INDEX_KEY") or "").encode("utf-8")
    if not key:
        raise RuntimeError("BLIND_INDEX_KEY is not set.")
    normalised = unicodedata.normalize("NFKC", value).strip().casefold().encode("utf-8")
    return hmac.new(key, normalised, hashlib.sha256).hexdigest()


def hash_token(token: str) -> str:
    """One-way hash for password-reset tokens, so the database never holds a
    usable token. Unkeyed SHA-256 is sufficient: the token is 256 bits of
    randomness, so there is nothing to brute-force."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_card_token() -> str:
    """128 bits, as a 22-character URL segment.

    Shorter than a reset token on purpose: this one is written to an NFC tag and
    may be printed under a QR code, and 128 bits is already far beyond anything
    that can be swept. Guessing one is not an attack that works.
    """
    return secrets.token_urlsafe(16)


# ---------------------------------------------------------------------------
# Emergency card presentation
# ---------------------------------------------------------------------------

# Conservative on purpose: at least nine characters, digits and separators only,
# no letters. Dosages ("200mg"), dates ("14 March 1996") and ordinary prose all
# fail to match, so nothing gets mangled into a link that should not be one.
PHONE_PATTERN = re.compile(r"(?<![\w/])(\(?\+?\d[\d\s().\-]{7,20}\d)(?![\w])")


def linkify_phones(value: str | None) -> Markup:
    """Turn phone numbers into tel: links, so a responder can tap to call.

    The source text is escaped piece by piece rather than escaped-then-scanned,
    so the pattern never sees HTML entities and cannot match inside one.
    """
    if not value:
        return Markup("")

    parts: list[Markup] = []
    cursor = 0
    for match in PHONE_PATTERN.finditer(value):
        parts.append(escape(value[cursor : match.start()]))
        raw = match.group(0)
        dialable = re.sub(r"[^\d+]", "", raw)
        parts.append(Markup('<a href="tel:{}" class="tel">{}</a>').format(dialable, raw))
        cursor = match.end()
    parts.append(escape(value[cursor:]))
    return Markup("").join(parts)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# Deliberately in-process: this app runs as a single Render web service, and an
# in-memory window is enough to blunt form spam and credential stuffing without
# adding a Redis dependency to a free-tier deployment.

_HITS: dict[str, deque[float]] = defaultdict(deque)


def reset_rate_limits() -> None:
    """Clear every recorded hit. Intended for tests, which would otherwise
    exhaust a shared per-IP budget across unrelated cases."""
    _HITS.clear()


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


# Kept as a private alias so existing internal callers read unchanged.
_client_ip = client_ip


def over_budget(bucket: str, max_requests: int, window_seconds: int) -> bool:
    """Record a hit and report whether this IP has exceeded ``bucket``.

    Unlike the decorator, this is called explicitly, so a view can charge only
    the requests it wants to charge -- failed emergency-token lookups, say,
    while letting every valid scan through untouched.
    """
    key = f"{bucket}:{client_ip()}"
    now = time.time()
    hits = _HITS[key]
    while hits and now - hits[0] > window_seconds:
        hits.popleft()
    if len(hits) >= max_requests:
        return True
    hits.append(now)
    return False


def rate_limit(max_requests: int, window_seconds: int, methods: tuple[str, ...] | None = None):
    """Reject more than ``max_requests`` from one IP per rolling window.

    ``methods`` limits which HTTP verbs count, so repeatedly opening a sign-in
    page is free while repeatedly submitting it is not.
    """

    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if methods is None or request.method in methods:
                key = f"{view.__name__}:{_client_ip()}"
                now = time.time()
                hits = _HITS[key]
                while hits and now - hits[0] > window_seconds:
                    hits.popleft()
                if len(hits) >= max_requests:
                    abort(429)
                hits.append(now)
            return view(*args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Auth guards
# ---------------------------------------------------------------------------


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            session["next_url"] = request.full_path if request.query_string else request.path
            flash("Please sign in to continue.", "info")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        user = g.get("user")
        if user is None:
            session["next_url"] = request.path
            return redirect(url_for("auth.login"))
        allowed = {
            e.strip().lower()
            for e in (current_app.config.get("ADMIN_EMAILS") or "").split(",")
            if e.strip()
        }
        if not allowed or (user.email or "").lower() not in allowed:
            abort(404)  # Don't advertise that the page exists.
        return view(*args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# Response hardening
# ---------------------------------------------------------------------------

CSP = "; ".join(
    [
        "default-src 'self'",
        # No inline scripts anywhere in this app -- keep it that way.
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
    ]
)


def apply_security_headers(response):
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()"
    )
    if current_app.config.get("IS_PRODUCTION"):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    # Personal health information and credential forms should never sit in a
    # shared cache, nor be replayed from the browser's back-forward cache.
    if request.path.startswith(
        ("/my-information", "/my-details", "/admin", "/account", "/sign-in", "/reset-password")
    ):
        response.headers["Cache-Control"] = "no-store, private"
    return response
