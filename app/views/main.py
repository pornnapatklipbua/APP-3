"""Public pages: awareness content and the tag request form."""

from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ..extensions import db
from ..mailer import send_tag_request_notification
from ..models import TagRequest
from ..security import admin_required, rate_limit

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


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/about-epilepsy")
def about():
    return render_template("about.html")


@bp.route("/seizure-first-aid")
def first_aid():
    return render_template("first_aid.html")


@bp.route("/request-a-tag", methods=["GET", "POST"])
@rate_limit(max_requests=5, window_seconds=900)
def request_tag():
    form = {}
    if request.method == "POST":
        form = {
            "full_name": _clean("full_name", 200),
            "email": _clean("email", 320),
            "phone": _clean("phone", 60),
            "postal_address": _clean("postal_address"),
            "tag_style": _clean("tag_style", 100),
            "engraving": _clean("engraving", 500),
            "message": _clean("message"),
        }

        errors = []
        if not form["full_name"]:
            errors.append("Please tell us your name.")
        if not form["email"] or "@" not in form["email"] or " " in form["email"]:
            errors.append("Please give an email address we can reply to.")
        if not form["postal_address"]:
            errors.append("Please give an address we can post the tag to.")
        if form["tag_style"] and form["tag_style"] not in TAG_STYLES:
            errors.append("Please choose one of the listed tag styles.")
        # Honeypot: a field hidden from people, irresistible to bots.
        if (request.form.get("website") or "").strip():
            errors.append("Please try again.")

        if errors:
            for message in errors:
                flash(message, "error")
        else:
            tag_request = TagRequest(
                user_id=g.user.id if g.get("user") else None,
                full_name=form["full_name"],
                email=form["email"],
                phone=form["phone"],
                postal_address=form["postal_address"],
                tag_style=form["tag_style"],
                engraving=form["engraving"],
                message=form["message"],
            )
            db.session.add(tag_request)
            db.session.commit()

            send_tag_request_notification(tag_request)
            return redirect(url_for("main.request_tag_sent"))

    return render_template("request_tag.html", form=form, tag_styles=TAG_STYLES)


@bp.route("/request-a-tag/sent")
def request_tag_sent():
    return render_template("request_tag_sent.html")


@bp.route("/privacy")
def privacy():
    return render_template("privacy.html")


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
