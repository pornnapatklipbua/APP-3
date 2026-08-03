"""Outbound notification for new tag requests.

Email is best-effort. A request is only ever confirmed to the visitor after it
is committed to the database, so a mail outage never loses one.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from flask import current_app


def smtp_configured() -> bool:
    cfg = current_app.config
    return bool(cfg.get("SMTP_HOST") and cfg.get("CONTACT_EMAIL"))


def _send(to_email: str, subject: str, body: str, reply_to: str | None = None) -> bool:
    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg.get("SMTP_FROM") or cfg.get("SMTP_USERNAME") or "no-reply@localhost"
    message["To"] = to_email
    if reply_to:
        message["Reply-To"] = reply_to
    message.set_content(body)

    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as smtp:
        smtp.starttls()
        if cfg.get("SMTP_USERNAME"):
            smtp.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"])
        smtp.send_message(message)
    return True


def send_password_reset(to_email: str, username: str, reset_url: str) -> bool:
    """Email a password reset link.

    Failures are logged, never surfaced: the caller returns the same response
    whether or not an address is registered, and an error here would give that
    away.
    """
    if not current_app.config.get("SMTP_HOST"):
        current_app.logger.error(
            "SMTP is not configured, so a password reset email could not be sent. "
            "Set SMTP_HOST and related variables, or nobody can recover an account."
        )
        # In development, print the link rather than leaving it unreachable.
        if not current_app.config.get("IS_PRODUCTION"):
            current_app.logger.warning("DEV ONLY - reset link: %s", reset_url)
        return False

    try:
        return _send(
            to_email=to_email,
            subject="Reset your Auraline password",
            body="\n".join(
                [
                    f"Hello {username},",
                    "",
                    "Someone asked to reset the password for your Auraline account.",
                    "Open the link below within the next hour to choose a new one:",
                    "",
                    reset_url,
                    "",
                    "The link can only be used once.",
                    "",
                    "If this was not you, you can ignore this email -- your password",
                    "has not been changed, and nobody can read your information",
                    "without it.",
                    "",
                    "Auraline",
                ]
            ),
        )
    except Exception:
        current_app.logger.error("Failed to send a password reset email.", exc_info=True)
        return False


def send_tag_request_notification(request_obj) -> bool:
    """Notify the site host. Returns True if the message was handed to SMTP."""
    if not smtp_configured():
        current_app.logger.info(
            "SMTP not configured; tag request #%s stored for review only.", request_obj.id
        )
        return False

    cfg = current_app.config
    message = EmailMessage()
    message["Subject"] = f"New epilepsy tag request (#{request_obj.id})"
    message["From"] = cfg.get("SMTP_FROM") or cfg["SMTP_USERNAME"]
    message["To"] = cfg["CONTACT_EMAIL"]
    if request_obj.contact_email:
        message["Reply-To"] = request_obj.contact_email

    message.set_content(
        "\n".join(
            [
                f"Request #{request_obj.id}",
                f"Received: {request_obj.created_at:%d %B %Y, %H:%M UTC}",
                "",
                f"Account:   {request_obj.contact_name or '-'}",
                f"Email:     {request_obj.contact_email or '-'}",
                f"Style:     {request_obj.tag_style or '-'}",
                f"QR code:   {'yes - print alongside the NFC chip' if request_obj.wants_qr else 'no - NFC only'}",
                "",
                "Delivery address:",
                request_obj.postal_address or "-",
                "",
                "Requested engraving:",
                request_obj.engraving or "-",
                "",
                "Message:",
                request_obj.message or "-",
                "",
                "Write the emergency link onto the tag from /admin/tag-requests.",
            ]
        )
    )

    try:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as smtp:
            smtp.starttls()
            if cfg.get("SMTP_USERNAME"):
                smtp.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"])
            smtp.send_message(message)
        return True
    except Exception:
        current_app.logger.error(
            "Failed to email tag request #%s; it remains in the database.",
            request_obj.id,
            exc_info=True,
        )
        return False
