"""Public pages: awareness content and the tag request form."""

from __future__ import annotations

import sqlalchemy as sa
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ..extensions import db
from ..i18n import bilingual, lurl_for, render_localised
from ..mailer import send_tag_request_notification
from ..models import EmergencyAccess, EmergencyCard, EpilepsyProfile, TagRequest, User
from ..security import admin_required, blind_index, login_required, rate_limit

bp = Blueprint("main", __name__)

MAX_FIELD = 2000

TAG_STYLES = (
    "Bracelet - silicone",
    "Bracelet - stainless steel",
    "Necklace / dog tag",
    "Shoe tag",
    "Wallet card",
    "Not sure yet - please advise",
)


def _clean(name: str, limit: int = MAX_FIELD) -> str:
    return (request.form.get(name) or "").strip()[:limit]


@bilingual(bp, "/")
def index():
    return render_localised("index.html")


@bilingual(bp, "/about-epilepsy")
def about():
    return render_localised("about.html")


@bilingual(bp, "/seizure-first-aid")
def first_aid():
    return render_localised("first_aid.html")


@bilingual(bp, "/request-a-tag")
def request_tag():
    """Entry point for the "Request a tag" links across the site.

    The form itself lives on the signed-in record page, so someone can read
    their information, edit it and order a tag without moving between pages.
    Signed-out visitors get an explanation of why an account is needed rather
    than a bare redirect to the sign-in form.
    """
    if g.get("user"):
        return redirect(lurl_for("records.my_information", _anchor="request-a-tag"))
    return render_localised("request_tag.html")


@bilingual(bp, "/my-information/request-a-tag", methods=["POST"])
@login_required
@rate_limit(max_requests=5, window_seconds=900, methods=("POST",))
def submit_tag_request():
    """Handle the tag request form embedded in the record page.

    Name and email are deliberately not asked for -- they are on the account,
    which is also what ties this request to the emergency link that gets
    written onto the finished tag.
    """
    postal_address = _clean("postal_address")
    tag_style = _clean("tag_style", 100)
    engraving = _clean("engraving", 500)
    message = _clean("message")
    wants_qr = bool(request.form.get("wants_qr"))

    errors = []
    if not postal_address:
        errors.append("Please give an address we can post the tag to.")
    if tag_style and tag_style not in TAG_STYLES:
        errors.append("Please choose one of the listed tag styles.")
    # Honeypot: a field hidden from people, irresistible to bots.
    if (request.form.get("website") or "").strip():
        errors.append("Please try again.")

    if errors:
        for problem in errors:
            flash(problem, "error")
        return redirect(lurl_for("records.my_information", _anchor="request-a-tag"))

    tag_request = TagRequest(
        user_id=g.user.id,
        postal_address=postal_address,
        tag_style=tag_style,
        engraving=engraving,
        message=message,
        wants_qr=wants_qr,
    )
    db.session.add(tag_request)
    db.session.commit()

    send_tag_request_notification(tag_request)
    flash(
        "Your tag request has been sent. We read every one ourselves and will "
        "reply by email, usually within a few days.",
        "success",
    )
    return redirect(url_for("records.my_information", _anchor="request-a-tag"))


@bilingual(bp, "/privacy")
def privacy():
    return render_localised("privacy.html")


@bp.route("/admin/tag-requests")
@admin_required
def admin_tag_requests():
    requests_ = db.session.scalars(
        db.select(TagRequest).order_by(TagRequest.created_at.desc()).limit(200)
    ).all()
    return render_template("admin/tag_requests.html", requests=requests_)


@bp.route("/admin/tag-requests/<int:request_id>/status", methods=["POST"])
@admin_required
def admin_update_status(request_id: int):
    tag_request = db.session.get(TagRequest, request_id)
    if tag_request is None:
        flash("That request no longer exists.", "error")
        return redirect(url_for("main.admin_tag_requests"))

    status = (request.form.get("status") or "").strip()
    if status not in {"new", "in-progress", "sent", "closed"}:
        flash("Unrecognised status.", "error")
    else:
        tag_request.status = status
        db.session.commit()
        flash(f"Request #{request_id} marked as {status}.", "success")
    return redirect(url_for("main.admin_tag_requests"))


def _reveal_and_log(user_id: int) -> tuple[EmergencyCard, bool]:
    """Mint a card if the account does not have one yet, and record who looked.

    This is the one path in the app where the site host can read a raw
    emergency link rather than just its existence -- everywhere else, the
    token is invisible to everyone but the tag's owner. It exists because
    fulfilling a physical tag needs the exact URL to write to it, and there is
    no way around that once fulfilment is done by hand rather than by the
    owner printing their own QR code.

    What keeps it honest: it reveals one link at a time, on an explicit click,
    never a bulk listing of tokens. And it is logged into the *owner's own*
    access log, by name, the same place an ordinary scan would appear -- so
    this is never a private admin action the owner has no way to see.
    """
    card, created = EmergencyCard.get_or_create(user_id)
    db.session.add(
        EmergencyAccess(
            card_id=card.id,
            source=EmergencyAccess.SOURCE_ADMIN_REVEAL,
            source_hash=blind_index(f"admin-reveal:{g.user.id}:{user_id}"),
        )
    )
    db.session.commit()
    return card, created


def _reveal_flash(card: EmergencyCard, created: bool, label: str) -> None:
    url = url_for("emergency.card", token=card.token, _external=True)
    note = (
        " A link had not been set up yet, so a new one was just created for them."
        if created
        else ""
    )
    flash(f"Emergency link for {label}: {url}{note}", "success")


@bp.route("/admin/tag-requests/<int:request_id>/reveal-emergency-link", methods=["POST"])
@admin_required
def admin_reveal_emergency_link(request_id: int):
    tag_request = db.session.get(TagRequest, request_id)
    if tag_request is None:
        flash("That request no longer exists.", "error")
        return redirect(url_for("main.admin_tag_requests"))

    if tag_request.user_id is None:
        flash(
            "This request was not submitted while signed in, so there is no "
            "account to link a tag to. Ask the requester to create an "
            "account and set up their own tag at /my-information/emergency "
            "-- you will then be able to reveal it here, or from Emergency "
            "links once they have registered.",
            "error",
        )
        return redirect(url_for("main.admin_tag_requests"))

    card, created = _reveal_and_log(tag_request.user_id)
    _reveal_flash(card, created, f"request #{request_id}")
    return redirect(url_for("main.admin_tag_requests"))


@bp.route("/admin/emergency-links")
@admin_required
def admin_emergency_links():
    """Every account, so the host can look up or hand out an emergency link
    without waiting for a shipping request to exist -- a lost tag being
    replaced in person, for instance.

    Deliberately not a page that displays tokens directly: it lists accounts
    and whether each has a card, and reveals one link at a time through the
    same logged path as the tag-request page.
    """
    query = (request.args.get("q") or "").strip()

    stmt = db.select(User).order_by(User.created_at.desc())
    if query:
        # The blind index is an exact-match lookup, not a substring search --
        # usernames and emails are encrypted, so there is no column to LIKE
        # against. A query that does not match either exactly returns nothing.
        lookup = blind_index(query)
        stmt = db.select(User).where(
            sa.or_(User.username_lookup == lookup, User.email_lookup == lookup)
        )

    users_ = db.session.scalars(stmt.limit(200)).all()
    cards_by_user = {c.user_id: c for c in db.session.scalars(db.select(EmergencyCard)).all()}
    profiles_by_user = {
        p.user_id: p for p in db.session.scalars(db.select(EpilepsyProfile)).all()
    }
    rows = [(u, cards_by_user.get(u.id), profiles_by_user.get(u.id)) for u in users_]

    return render_template("admin/emergency_links.html", rows=rows, query=query)


@bp.route("/admin/emergency-links/<int:user_id>/reveal", methods=["POST"])
@admin_required
def admin_reveal_user_link(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        flash("That account no longer exists.", "error")
        return redirect(url_for("main.admin_emergency_links"))

    card, created = _reveal_and_log(user_id)
    _reveal_flash(card, created, user.username)
    return redirect(url_for("main.admin_emergency_links"))
