"""The signed-in area: reading, editing, exporting and deleting your own record.

Every query in this module is scoped by ``g.user.id``. No route accepts a record
identifier from the URL, so there is no object-reference to tamper with -- you
can only ever reach your own information.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from ..extensions import db
from ..models import EmergencyCard, EpilepsyProfile
from ..security import blind_index, login_required, new_card_token

bp = Blueprint("records", __name__)

MAX_FIELD = 4000


def _own_profile() -> EpilepsyProfile | None:
    return db.session.scalar(db.select(EpilepsyProfile).filter_by(user_id=g.user.id))


def _own_card() -> EmergencyCard | None:
    return db.session.scalar(db.select(EmergencyCard).filter_by(user_id=g.user.id))


def _issue_card(existing: EmergencyCard | None = None) -> EmergencyCard:
    """Mint a fresh token. Collisions are not a practical concern at 128 bits,
    but the loop costs nothing and turns an astronomically unlikely integrity
    error into a retry."""
    for _ in range(5):
        token = new_card_token()
        lookup = blind_index(token)
        if db.session.scalar(db.select(EmergencyCard).filter_by(token_lookup=lookup)):
            continue
        if existing is None:
            card = EmergencyCard(user_id=g.user.id, token=token, token_lookup=lookup)
            db.session.add(card)
            return card
        existing.token = token
        existing.token_lookup = lookup
        existing.regenerated_at = datetime.now(timezone.utc)
        existing.accesses.clear()  # the log belonged to the retired tag
        return existing
    raise RuntimeError("Could not allocate an unused emergency card token.")


@bp.route("/my-information")
@login_required
def my_information():
    """Read-only view of nothing but this user's own epilepsy information."""
    profile = _own_profile()
    return render_template(
        "records/my_information.html",
        profile=profile,
        sections=EpilepsyProfile.SECTIONS,
    )


@bp.route("/my-details", methods=["GET", "POST"])
@login_required
def edit():
    profile = _own_profile()

    if request.method == "POST":
        if profile is None:
            profile = EpilepsyProfile(user_id=g.user.id)
            db.session.add(profile)

        for name in EpilepsyProfile.field_names():
            value = (request.form.get(name) or "").strip()[:MAX_FIELD]
            setattr(profile, name, value or None)

        db.session.commit()
        flash("Your information has been saved.", "success")
        return redirect(url_for("records.my_information"))

    return render_template(
        "records/edit.html",
        profile=profile,
        sections=EpilepsyProfile.SECTIONS,
    )


@bp.route("/my-information/download")
@login_required
def download():
    """Take a copy with you. The export is generated per request and never stored."""
    profile = _own_profile()
    payload = {
        "exported_for": g.user.email,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "information": {
            name: getattr(profile, name) for name in EpilepsyProfile.field_names()
        }
        if profile
        else {},
    }
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    return Response(
        body,
        mimetype="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="my-epilepsy-information.json"',
            "Cache-Control": "no-store, private",
        },
    )


@bp.route("/my-information/emergency")
@login_required
def emergency():
    """Manage the tag: the URL to write to it, whether it is live, and who has
    opened it."""
    card = _own_card()
    profile = _own_profile()
    return render_template(
        "records/emergency.html",
        card=card,
        card_url=url_for("emergency.card", token=card.token, _external=True) if card else None,
        profile=profile,
        preview_sections=profile.emergency_sections() if profile else [],
    )


@bp.route("/my-information/emergency/create", methods=["POST"])
@login_required
def emergency_create():
    if _own_card() is not None:
        flash("You already have an emergency tag link.", "info")
        return redirect(url_for("records.emergency"))

    _issue_card()
    db.session.commit()
    flash("Your emergency link is ready to write to a tag.", "success")
    return redirect(url_for("records.emergency"))


@bp.route("/my-information/emergency/regenerate", methods=["POST"])
@login_required
def emergency_regenerate():
    card = _own_card()
    if card is None:
        return redirect(url_for("records.emergency"))

    _issue_card(existing=card)
    db.session.commit()
    flash(
        "A new link has been issued. The old one no longer works, so any tag "
        "or card you have already made must be written again.",
        "success",
    )
    return redirect(url_for("records.emergency"))


@bp.route("/my-information/emergency/toggle", methods=["POST"])
@login_required
def emergency_toggle():
    card = _own_card()
    if card is None:
        return redirect(url_for("records.emergency"))

    card.is_active = not card.is_active
    db.session.commit()
    flash(
        "Your tag is live again." if card.is_active
        else "Your tag is switched off. Scanning it now shows nothing.",
        "success",
    )
    return redirect(url_for("records.emergency"))


@bp.route("/my-information/emergency/qr.svg")
@login_required
def emergency_qr():
    """A printable fallback. NFC is not universal -- older handsets, a locked
    phone, a responder who does not know to tap -- and a QR code beside the tag
    costs nothing and works everywhere a camera does."""
    import io

    import segno

    card = _own_card()
    if card is None:
        abort(404)

    buffer = io.BytesIO()
    segno.make(
        url_for("emergency.card", token=card.token, _external=True), error="m"
    ).save(buffer, kind="svg", scale=5, border=2, dark="#1c1922", light="#ffffff")

    return Response(
        buffer.getvalue(),
        mimetype="image/svg+xml",
        headers={"Cache-Control": "no-store, private", "Referrer-Policy": "no-referrer"},
    )


@bp.route("/my-details/delete", methods=["POST"])
@login_required
def delete():
    profile = _own_profile()
    if profile is None:
        flash("There was nothing stored to delete.", "info")
    else:
        db.session.delete(profile)
        db.session.commit()
        flash("Your epilepsy information has been permanently deleted.", "success")
    return redirect(url_for("records.my_information"))
