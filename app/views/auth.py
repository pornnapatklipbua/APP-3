"""Accounts held by this site: registration, sign-in, password change and reset.

Two rules run through this module:

* Failures are indistinguishable. A wrong username and a wrong password give the
  same message and take the same time, so the responses cannot be used to work
  out who has an account here.
* Nothing reusable is stored. Passwords exist only as Argon2id hashes; reset
  tokens only as SHA-256 hashes.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..extensions import db
from ..i18n import bilingual, lurl_for, render_localised
from ..mailer import send_password_reset
from ..models import PasswordResetToken, User
from ..security import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    blind_index,
    hash_password,
    hash_token,
    login_required,
    new_token,
    password_problems,
    rate_limit,
    verify_password,
)

bp = Blueprint("auth", __name__)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")

RESET_TOKEN_LIFETIME = timedelta(hours=1)

# Deliberately identical for every failure mode.
BAD_CREDENTIALS = "Incorrect username or password."


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_next(candidate: str | None) -> str:
    """Only ever redirect to a path on this site."""
    if not candidate:
        return lurl_for("records.my_information")
    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc or not candidate.startswith("/") or candidate.startswith("//"):
        return lurl_for("records.my_information")
    return candidate


def _start_session(user: User, destination: str, message: str | None = None):
    # New session identity on privilege change, to defeat session fixation.
    # Anything worth saying must be flashed *after* the clear, or it is wiped
    # along with everything else.
    session.clear()
    session["user_id"] = user.id
    session["epoch"] = user.session_epoch or 0
    session.permanent = True
    if message:
        flash(message, "success")
    return redirect(destination)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


@bilingual(bp, "/create-account", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=900, methods=("POST",))
def register():
    if g.get("user"):
        return redirect(lurl_for("records.my_information"))

    form = {"username": "", "email": ""}

    if request.method == "POST":
        form["username"] = (request.form.get("username") or "").strip()
        form["email"] = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("password_confirm") or ""

        errors: list[str] = []

        if not USERNAME_PATTERN.match(form["username"]):
            errors.append(
                "Usernames are 3 to 32 characters, using letters, numbers, dots, "
                "hyphens and underscores."
            )
        if not EMAIL_PATTERN.match(form["email"]) or len(form["email"]) > 320:
            errors.append("Please enter a valid email address.")
        if password != confirm:
            errors.append("The two passwords do not match.")

        errors.extend(password_problems(password, form["username"], form["email"]))

        if (request.form.get("website") or "").strip():
            errors.append("Please try again.")

        if not errors:
            username_lookup = blind_index(form["username"])
            email_lookup = blind_index(form["email"])

            if db.session.scalar(db.select(User).filter_by(username_lookup=username_lookup)):
                errors.append("That username is already taken.")
            elif db.session.scalar(db.select(User).filter_by(email_lookup=email_lookup)):
                # This does disclose that an address is registered. The
                # alternative -- silently accepting a duplicate and emailing the
                # original owner -- trades a small disclosure for a confusing
                # dead end, which is the worse outcome for a medical record.
                errors.append(
                    "There is already an account for that email address. "
                    "Try signing in, or reset your password."
                )
            else:
                user = User(
                    username=form["username"],
                    username_lookup=username_lookup,
                    email=form["email"],
                    email_lookup=email_lookup,
                    password_hash=hash_password(password),
                )
                user.register_successful_login()
                db.session.add(user)
                db.session.commit()

                return _start_session(
                    user, _safe_next(session.get("next_url")), "Your account is ready."
                )

        for message in errors:
            flash(message, "error")

    return render_localised(
        "auth/register.html",
        form=form,
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
    )


# ---------------------------------------------------------------------------
# Sign in / out
# ---------------------------------------------------------------------------


@bilingual(bp, "/sign-in", methods=["GET", "POST"])
@rate_limit(max_requests=10, window_seconds=900, methods=("POST",))
def login():
    if g.get("user"):
        return redirect(lurl_for("records.my_information"))

    username = ""

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if request.args.get("next"):
            session["next_url"] = _safe_next(request.args["next"])

        user = None
        if username:
            user = db.session.scalar(
                db.select(User).filter_by(username_lookup=blind_index(username))
            )

        if user is not None and user.is_locked:
            minutes = max(1, round(user.lockout_seconds_remaining() / 60))
            flash(
                f"Too many failed attempts. Try again in about {minutes} "
                f"minute{'' if minutes == 1 else 's'}, or reset your password.",
                "error",
            )
            return render_localised("auth/sign_in.html", username=username)

        # Runs even when `user` is None, against a dummy hash, so a missing
        # account is not measurably faster to reject than a wrong password.
        is_valid, replacement_hash = verify_password(
            user.password_hash if user else None, password
        )

        if user is not None and is_valid:
            if replacement_hash:
                # Argon2 parameters were raised since they last signed in.
                user.password_hash = replacement_hash
            user.register_successful_login()
            db.session.commit()

            destination = _safe_next(session.get("next_url"))
            return _start_session(user, destination, f"Signed in as {user.username}.")

        if user is not None:
            user.register_failed_login()
            db.session.commit()

        flash(BAD_CREDENTIALS, "error")

    return render_localised("auth/sign_in.html", username=username)


@bilingual(bp, "/sign-out", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(lurl_for("main.index"))


# ---------------------------------------------------------------------------
# Account settings
# ---------------------------------------------------------------------------


@bilingual(bp, "/account")
@login_required
def account():
    return render_localised(
        "auth/account.html",
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
    )


@bilingual(bp, "/account/password", methods=["POST"])
@login_required
@rate_limit(max_requests=10, window_seconds=900, methods=("POST",))
def change_password():
    user = g.user
    current = request.form.get("current_password") or ""
    new = request.form.get("new_password") or ""
    confirm = request.form.get("new_password_confirm") or ""

    errors: list[str] = []

    is_valid, _ = verify_password(user.password_hash, current)
    if not is_valid:
        errors.append("Your current password is not correct.")
    if new != confirm:
        errors.append("The two new passwords do not match.")
    if is_valid and new == current:
        errors.append("Please choose a password you have not used here before.")

    errors.extend(password_problems(new, user.username, user.email))

    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(lurl_for("auth.account"))

    user.password_hash = hash_password(new)
    user.password_changed_at = _utcnow()
    user.session_epoch = (user.session_epoch or 0) + 1
    _invalidate_reset_tokens(user)
    db.session.commit()

    # Our own session carries the old epoch, so re-establish it rather than
    # signing the person out of the device they are actually using.
    session["epoch"] = user.session_epoch

    flash("Your password has been changed. Any other devices have been signed out.", "success")
    return redirect(lurl_for("auth.account"))


@bilingual(bp, "/account/delete", methods=["POST"])
@login_required
def delete_account():
    user = g.user
    password = request.form.get("password") or ""

    is_valid, _ = verify_password(user.password_hash, password)
    if not is_valid:
        flash("Please enter your current password to delete your account.", "error")
        return redirect(lurl_for("auth.account"))

    db.session.delete(user)  # cascades to the record and reset tokens
    db.session.commit()
    session.clear()

    flash("Your account and everything stored with it have been deleted.", "success")
    return redirect(lurl_for("main.index"))


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------


def _invalidate_reset_tokens(user: User) -> None:
    now = _utcnow()
    for token in user.reset_tokens:
        if token.used_at is None:
            token.used_at = now


@bilingual(bp, "/forgot-password", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=900, methods=("POST",))
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()

        if email and EMAIL_PATTERN.match(email):
            user = db.session.scalar(
                db.select(User).filter_by(email_lookup=blind_index(email))
            )
            if user is not None:
                _invalidate_reset_tokens(user)
                raw_token = new_token()
                db.session.add(
                    PasswordResetToken(
                        user_id=user.id,
                        token_hash=hash_token(raw_token),
                        expires_at=_utcnow() + RESET_TOKEN_LIFETIME,
                    )
                )
                db.session.commit()

                send_password_reset(
                    to_email=user.email,
                    username=user.username,
                    # Language-aware: someone who asked from the Thai page gets
                    # a link back into the Thai page.
                    reset_url=lurl_for(
                        "auth.reset_password", token=raw_token, _external=True
                    ),
                )

        # Identical response either way, so this page cannot be used to discover
        # which addresses are registered.
        return redirect(lurl_for("auth.forgot_password_sent"))

    return render_localised("auth/forgot_password.html")


@bilingual(bp, "/forgot-password/sent")
def forgot_password_sent():
    return render_localised("auth/forgot_password_sent.html")


@bilingual(bp, "/reset-password/<token>", methods=["GET", "POST"])
@rate_limit(max_requests=10, window_seconds=900)
def reset_password(token: str):
    record = db.session.scalar(
        db.select(PasswordResetToken).filter_by(token_hash=hash_token(token))
    )

    if record is None or not record.is_usable:
        flash(
            "That reset link has expired or has already been used. "
            "Please request a new one.",
            "error",
        )
        return redirect(lurl_for("auth.forgot_password"))

    user = record.user

    if request.method == "POST":
        new = request.form.get("new_password") or ""
        confirm = request.form.get("new_password_confirm") or ""

        errors: list[str] = []
        if new != confirm:
            errors.append("The two passwords do not match.")
        errors.extend(password_problems(new, user.username, user.email))

        if errors:
            for message in errors:
                flash(message, "error")
            return render_localised(
                "auth/reset_password.html",
                token=token,
                min_length=MIN_PASSWORD_LENGTH,
                max_length=MAX_PASSWORD_LENGTH,
            )

        user.password_hash = hash_password(new)
        user.password_changed_at = _utcnow()
        user.session_epoch = (user.session_epoch or 0) + 1
        user.failed_login_count = 0
        user.locked_until = None
        record.used_at = _utcnow()
        _invalidate_reset_tokens(user)
        db.session.commit()

        flash("Your password has been reset. You can sign in now.", "success")
        return redirect(lurl_for("auth.login"))

    return render_localised(
        "auth/reset_password.html",
        token=token,
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
    )
