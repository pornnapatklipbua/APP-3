"""The page an NFC scan lands on.

This is the only route on the site that shows one person's health information to
someone who is not signed in. The token in the URL is the entire authorisation,
so the rules here are tighter than anywhere else:

* 128-bit token, looked up through a keyed blind index -- the raw token is never
  stored in a form the database alone can yield.
* No referrer, ever. A single outbound link leaking the URL in a Referer header
  would hand the card to a third party permanently.
* Never cached, never indexed, and excluded in robots.txt.
* Wrong tokens are rate limited; correct ones never are. A paramedic must not be
  turned away because someone else was probing the site an hour earlier.
"""

from __future__ import annotations

from flask import Blueprint, Response, abort, current_app, render_template, request

from ..extensions import db
from ..models import EmergencyAccess, EmergencyCard
from ..security import blind_index, client_ip, over_budget

bp = Blueprint("emergency", __name__)


def _harden(response: Response) -> Response:
    # strict-origin-when-cross-origin, the site-wide default, would still send
    # this site's origin outward. Here we send nothing at all.
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
    return response


@bp.route("/e/<token>")
def card(token: str):
    lookup = blind_index(token)
    record = db.session.scalar(db.select(EmergencyCard).filter_by(token_lookup=lookup))

    if record is None:
        # Only failures count towards a budget, so a genuine scan always works
        # however much probing has happened from the same address.
        if over_budget("emergency-miss", max_requests=20, window_seconds=600):
            abort(429)
        return _harden(
            current_app.make_response((render_template("emergency/unknown.html"), 404))
        )

    if not record.is_active:
        return _harden(
            current_app.make_response((render_template("emergency/inactive.html"), 410))
        )

    _log_access(record)

    profile = record.user.profile
    return _harden(
        current_app.make_response(
            render_template(
                "emergency/card.html",
                profile=profile,
                sections=profile.emergency_sections() if profile else [],
                owner=record.user,
            )
        )
    )


def _log_access(record: EmergencyCard) -> None:
    """Record the view so the owner can see their card being used.

    Failure here must never stop the page rendering -- the information is the
    point, the audit trail is a courtesy.
    """
    try:
        db.session.add(
            EmergencyAccess(
                card_id=record.id,
                source_hash=blind_index("scanner:" + client_ip()),
            )
        )
        db.session.flush()

        keep = db.session.scalars(
            db.select(EmergencyAccess.id)
            .filter_by(card_id=record.id)
            .order_by(EmergencyAccess.accessed_at.desc())
            .limit(EmergencyAccess.RETAIN_PER_CARD)
        ).all()
        db.session.query(EmergencyAccess).filter(
            EmergencyAccess.card_id == record.id,
            EmergencyAccess.id.notin_(keep),
        ).delete(synchronize_session=False)

        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.error("Could not log an emergency card access.", exc_info=True)


@bp.route("/robots.txt")
def robots():
    body = "\n".join(
        [
            "User-agent: *",
            "Disallow: /e/",
            "Disallow: /my-information",
            "Disallow: /my-details",
            "Disallow: /account",
            "Disallow: /admin",
            "Disallow: /reset-password",
            "",
        ]
    )
    return Response(body, mimetype="text/plain")
