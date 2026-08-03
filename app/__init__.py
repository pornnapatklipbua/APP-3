"""Application factory."""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from flask import Flask, g, render_template, session
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

from .config import Config  # noqa: E402  (must follow load_dotenv)
from .extensions import csrf, db  # noqa: E402
from .security import apply_security_headers, linkify_phones  # noqa: E402


def create_app(config_object: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    # Render terminates TLS at its edge. Without this, url_for(_external=True)
    # builds http:// links -- including the ones emailed in password resets --
    # and the rate limiter sees Render's proxy IP instead of the visitor's.
    if app.config["IS_PRODUCTION"]:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    _validate_config(app)

    db.init_app(app)
    csrf.init_app(app)

    from .views import auth, emergency, main, records

    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(records.bp)
    app.register_blueprint(emergency.bp)

    app.jinja_env.filters["phones"] = linkify_phones

    # Templates link within whichever language they are being served in, so a
    # Thai page never drops the visitor back into English mid-journey. Safe to
    # apply globally: endpoints with no Thai twin fall through unchanged.
    from .i18n import lurl_for

    app.jinja_env.globals["url_for"] = lurl_for

    @app.before_request
    def load_logged_in_user() -> None:
        from .models import User

        user_id = session.get("user_id")
        g.user = db.session.get(User, user_id) if user_id else None

        if user_id and g.user is None:
            # The account was deleted out from under a live session.
            session.clear()
        elif g.user is not None and session.get("epoch") != (g.user.session_epoch or 0):
            # The password changed elsewhere; this session is stale.
            session.clear()
            g.user = None

    @app.context_processor
    def inject_globals() -> dict:
        from .i18n import language_context

        return {"current_user": g.get("user"), **language_context()}

    app.after_request(apply_security_headers)

    from .i18n import render_localised

    @app.errorhandler(404)
    def not_found(_):
        return render_localised("errors/404.html"), 404

    @app.errorhandler(429)
    def too_many(_):
        return render_localised("errors/429.html"), 429

    @app.errorhandler(500)
    def server_error(_):
        db.session.rollback()
        return render_localised("errors/500.html"), 500

    with app.app_context():
        try:
            db.create_all()
        except Exception:
            # On a first deploy every gunicorn worker boots at once, checks for
            # the tables, finds none, and issues CREATE TABLE. One wins and the
            # rest hit "already exists". The schema is correct either way, so
            # log it rather than letting a losing worker crash the deploy.
            app.logger.warning(
                "create_all() failed; assuming another worker created the schema.",
                exc_info=True,
            )

        try:
            from .schema_guard import ensure_columns

            ensure_columns(app, db)
        except Exception:
            # Never let a schema-guard problem take the whole app down --
            # worst case, whatever it would have fixed still needs a human,
            # exactly as it did before this existed.
            app.logger.error("schema_guard.ensure_columns() failed.", exc_info=True)

    if not app.debug:
        logging.basicConfig(level=logging.INFO)

    return app


def _validate_config(app: Flask) -> None:
    """Fail loudly in production rather than running in a half-secure state."""
    if not app.config["IS_PRODUCTION"]:
        # Local development gets throwaway keys so the app runs straight after a
        # clone. Neither is ever used when FLASK_ENV=production.
        if not app.config.get("FIELD_ENCRYPTION_KEYS"):
            from cryptography.fernet import Fernet

            dev_key = os.environ.setdefault("DEV_FERNET_KEY", Fernet.generate_key().decode())
            app.config["FIELD_ENCRYPTION_KEYS"] = dev_key
            app.logger.warning(
                "FIELD_ENCRYPTION_KEYS unset - generated an ephemeral development key. "
                "Existing local rows will not decrypt across restarts."
            )
        if not app.config.get("BLIND_INDEX_KEY"):
            import secrets as _secrets

            dev_index = os.environ.setdefault("DEV_BLIND_INDEX_KEY", _secrets.token_urlsafe(32))
            app.config["BLIND_INDEX_KEY"] = dev_index
            app.logger.warning(
                "BLIND_INDEX_KEY unset - generated an ephemeral development key. "
                "Existing local accounts will not be findable across restarts."
            )
        return

    missing = [
        name
        for name in ("SECRET_KEY", "FIELD_ENCRYPTION_KEYS", "BLIND_INDEX_KEY")
        if not app.config.get(name)
    ]
    if app.config.get("SECRET_KEY") == "dev-only-insecure-key-change-me":
        missing.append("SECRET_KEY (still set to the development default)")
    if missing:
        raise RuntimeError(
            "Refusing to start in production without: " + ", ".join(missing)
        )
