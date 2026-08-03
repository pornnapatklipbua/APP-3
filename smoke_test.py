"""Standalone smoke test. No pytest required:

    python smoke_test.py

Exercises routing, registration, sign-in, lockout, password reset, access
control, CSRF, and the encryption round-trip -- including reading the raw
database back with SQL to prove nothing sensitive is stored in the clear.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
import tempfile
import traceback
from pathlib import Path

from cryptography.fernet import Fernet

TMP_DIR = Path(tempfile.mkdtemp(prefix="auraline-test-"))
DB_PATH = TMP_DIR / "test.db"

os.environ["FLASK_ENV"] = "development"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["FIELD_ENCRYPTION_KEYS"] = Fernet.generate_key().decode()
os.environ["BLIND_INDEX_KEY"] = secrets.token_urlsafe(32)
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH.as_posix()}"
os.environ["ADMIN_EMAILS"] = "host@example.com"
# Keep hashing cheap so the suite runs quickly; production uses the real values.
os.environ["ARGON2_TIME_COST"] = "1"
os.environ["ARGON2_MEMORY_KIB"] = "8192"

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import (  # noqa: E402
    EmergencyAccess,
    EmergencyCard,
    EpilepsyProfile,
    PasswordResetToken,
    TagRequest,
    User,
)

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []

GOOD_PASSWORD = "harbour-lantern-quiet-33"
NEW_PASSWORD = "seventeen-copper-window"


def csrf_from(html: str) -> str:
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not match:
        raise AssertionError("no csrf_token field found in page")
    return match.group(1)


def token_for(client, path: str) -> str:
    return csrf_from(client.get(path).get_data(as_text=True))


def clear_limits() -> None:
    """Every test client shares one source IP, so the per-IP budget has to be
    reset between phases that are not themselves testing rate limits."""
    from app.security import reset_rate_limits

    reset_rate_limits()


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}{(' - ' + detail) if detail else ''}")


def register(client, username: str, email: str, password: str, **extra):
    data = {
        "csrf_token": token_for(client, "/create-account"),
        "username": username,
        "email": email,
        "password": password,
        "password_confirm": password,
    }
    data.update(extra)
    return client.post("/create-account", data=data, follow_redirects=True)


def sign_in(client, username: str, password: str):
    return client.post(
        "/sign-in",
        data={
            "csrf_token": token_for(client, "/sign-in"),
            "username": username,
            "password": password,
        },
        follow_redirects=True,
    )


def main() -> int:
    app = create_app()
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()

    print("\nPublic pages")
    for path in [
        "/",
        "/about-epilepsy",
        "/seizure-first-aid",
        "/request-a-tag",
        "/privacy",
        "/sign-in",
        "/create-account",
        "/forgot-password",
    ]:
        response = client.get(path)
        check(f"GET {path} -> 200", response.status_code == 200, f"got {response.status_code}")

    check("GET /no-such-page -> 404", client.get("/no-such-page").status_code == 404)

    print("\nSecurity headers")
    response = client.get("/")
    for header in [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
    ]:
        check(f"{header} present", header in response.headers)
    check(
        "CSP forbids inline script",
        "'unsafe-inline'" not in response.headers.get("Content-Security-Policy", ""),
    )
    check(
        "Sign-in page is uncacheable",
        "no-store" in client.get("/sign-in").headers.get("Cache-Control", ""),
    )

    print("\nAccess control (signed out)")
    for path in ["/my-information", "/my-details", "/my-information/download", "/account"]:
        response = client.get(path)
        check(
            f"GET {path} redirects to sign-in",
            response.status_code == 302 and "/sign-in" in response.headers.get("Location", ""),
            f"got {response.status_code}",
        )
    check(
        "GET /admin/tag-requests hidden from anonymous",
        client.get("/admin/tag-requests").status_code in (302, 404),
    )

    print("\nCSRF")
    check(
        "POST without CSRF token rejected",
        client.post("/sign-in", data={"username": "x", "password": "y"}).status_code == 400,
    )

    print("\nPassword policy")
    from app.security import password_problems

    with app.app_context():
        check("Short password rejected", bool(password_problems("short1")))
        check("Common password rejected", bool(password_problems("password123456")))
        check(
            "Password containing username rejected",
            bool(password_problems("morrigan-is-my-name", username="morrigan")),
        )
        check("Low-variety password rejected", bool(password_problems("abababababababab")))
        check("Good passphrase accepted", password_problems(GOOD_PASSWORD) == [])
        check(
            "Over-long password rejected",
            bool(password_problems("a-very-long-passphrase-" + "x" * 200)),
        )

    print("\nRegistration")
    clear_limits()
    # A fresh client: the access-control checks above left a stored `next_url`
    # pointing at the admin page, which this account is correctly refused.
    client = app.test_client()
    response = register(client, "sam.okafor", "sam@example.com", GOOD_PASSWORD)
    check("Account created", response.status_code == 200, f"got {response.status_code}")
    check("Signed in after registering", "Your account is ready" in response.get_data(as_text=True))
    check(
        "Lands on the record page",
        "My information" in response.get_data(as_text=True),
    )

    client.post("/sign-out", data={"csrf_token": token_for(client, "/")}, follow_redirects=True)

    other = app.test_client()
    response = register(other, "sam.okafor", "different@example.com", GOOD_PASSWORD)
    check("Duplicate username rejected", "already taken" in response.get_data(as_text=True))

    response = register(other, "someone.else", "sam@example.com", GOOD_PASSWORD)
    check(
        "Duplicate email rejected",
        "already an account for that email" in response.get_data(as_text=True),
    )

    response = register(other, "bad user!", "bad@example.com", GOOD_PASSWORD)
    check("Invalid username rejected", "Usernames are 3 to 32" in response.get_data(as_text=True))

    response = register(other, "weakling", "weak@example.com", "password")
    check("Weak password rejected at signup", "at least 12" in response.get_data(as_text=True).lower())

    response = register(other, "honeytrap", "bot@example.com", GOOD_PASSWORD, website="spam")
    with app.app_context():
        bot = db.session.scalar(db.select(User).filter_by(username_lookup=_bi(app, "honeytrap")))
    check("Honeypot registration blocked", bot is None)

    with app.app_context():
        count = db.session.scalar(db.select(db.func.count()).select_from(User))
    check("Only one account exists", count == 1, f"{count} users")

    print("\nCredential storage")
    with app.app_context():
        row = db.session.execute(
            db.text("SELECT username, email, password_hash FROM users LIMIT 1")
        ).first()
        raw_username, raw_email, raw_hash = row
        check("Username not stored in plaintext", "sam.okafor" not in str(raw_username))
        check("Email not stored in plaintext", "sam@example.com" not in str(raw_email))
        check("Password not stored in plaintext", GOOD_PASSWORD not in str(raw_hash))
        check(
            "Password hashed with Argon2id",
            str(raw_hash).startswith("$argon2id$"),
            str(raw_hash)[:20],
        )
        check(
            "Hash is salted (no bare digest)",
            len(str(raw_hash)) > 60 and "$" in str(raw_hash),
        )

    print("\nSign in")
    clear_limits()
    check("Wrong password refused", "Incorrect username or password" in sign_in(client, "sam.okafor", "not-the-password").get_data(as_text=True))
    check(
        "Unknown user gives identical message",
        "Incorrect username or password" in sign_in(client, "nobody.here", "whatever-at-all").get_data(as_text=True),
    )

    response = sign_in(client, "sam.okafor", GOOD_PASSWORD)
    check("Correct password accepted", "Signed in as sam.okafor" in response.get_data(as_text=True))
    check("Username lookup is case-insensitive", "Signed in" in sign_in(app.test_client(), "SAM.OKAFOR", GOOD_PASSWORD).get_data(as_text=True))

    print("\nRehash on parameter upgrade")
    clear_limits()
    with app.app_context():
        before = db.session.execute(
            db.text("SELECT password_hash FROM users WHERE username_lookup = :u"),
            {"u": _bi(app, "sam.okafor")},
        ).scalar()
    check("Stored at the original cost", "m=8192" in before, before[:32])

    # Simulate raising the work factor after accounts already exist.
    app.config["ARGON2_MEMORY_KIB"] = 16384
    upgrader = app.test_client()
    response = sign_in(upgrader, "sam.okafor", GOOD_PASSWORD)
    check("Sign-in still works after raising cost", "Signed in as" in response.get_data(as_text=True))
    with app.app_context():
        after = db.session.execute(
            db.text("SELECT password_hash FROM users WHERE username_lookup = :u"),
            {"u": _bi(app, "sam.okafor")},
        ).scalar()
    check("Hash silently upgraded on sign-in", "m=16384" in after, after[:32])
    app.config["ARGON2_MEMORY_KIB"] = 8192
    # Re-verify against the upgraded hash under the original settings, proving
    # an older-parameter server can still read what a newer one wrote.
    check(
        "Upgraded hash still verifies",
        "Signed in as" in sign_in(app.test_client(), "sam.okafor", GOOD_PASSWORD).get_data(as_text=True),
    )

    print("\nRecord lifecycle")
    with app.app_context():
        stranger = User(
            username="stranger",
            username_lookup=_bi(app, "stranger"),
            email="stranger@example.com",
            email_lookup=_bi(app, "stranger@example.com"),
            password_hash="x",
        )
        db.session.add(stranger)
        db.session.commit()
        db.session.add(
            EpilepsyProfile(user_id=stranger.id, full_name="Someone Else", medications="Ethosuximide")
        )
        db.session.commit()
        stranger_id = stranger.id

    response = client.post(
        "/my-details",
        data={
            "csrf_token": token_for(client, "/my-details"),
            "full_name": "Sam Okafor",
            "seizure_types": "Focal aware, tonic-clonic",
            "first_aid_notes": "Time it. Cushion my head.",
            "medications": "Lamotrigine 200mg twice daily",
            "emergency_contact_1": "Ada Okafor, sister, 07700 900456",
            # The fields a responder needs first, so the emergency card's
            # ordering can actually be asserted below.
            "allergies": "Penicillin - anaphylaxis",
            "implanted_device": "VNS fitted 2022 - magnet in my bag",
            "rescue_medication": "Buccal midazolam 10mg, in my bag",
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    check("Record saved", response.status_code == 200)
    check("Saved value renders back", "Lamotrigine 200mg twice daily" in body)
    check("No cross-user leakage", "Someone Else" not in body and "Ethosuximide" not in body)
    check(
        "Record page is uncacheable",
        "no-store" in client.get("/my-information").headers.get("Cache-Control", ""),
    )

    response = client.get("/my-information/download")
    check("Download works", response.status_code == 200)
    check("Download contains my data", "Lamotrigine" in response.get_data(as_text=True))

    with app.app_context():
        raw = db.session.execute(
            db.text("SELECT medications FROM epilepsy_profiles WHERE user_id != :s"),
            {"s": stranger_id},
        ).first()
        check("Medication encrypted at rest", raw is not None and "Lamotrigine" not in str(raw[0]))
        check("Ciphertext looks like Fernet", raw is not None and str(raw[0]).startswith("gAAAAA"))

    print("\nChange password")
    clear_limits()
    response = client.post(
        "/account/password",
        data={
            "csrf_token": token_for(client, "/account"),
            "current_password": "wrong-password-entirely",
            "new_password": NEW_PASSWORD,
            "new_password_confirm": NEW_PASSWORD,
        },
        follow_redirects=True,
    )
    check("Wrong current password refused", "current password is not correct" in response.get_data(as_text=True))

    # A second signed-in device, to prove it gets signed out.
    second_device = app.test_client()
    sign_in(second_device, "sam.okafor", GOOD_PASSWORD)
    check("Second device signed in", second_device.get("/my-information").status_code == 200)

    response = client.post(
        "/account/password",
        data={
            "csrf_token": token_for(client, "/account"),
            "current_password": GOOD_PASSWORD,
            "new_password": NEW_PASSWORD,
            "new_password_confirm": NEW_PASSWORD,
        },
        follow_redirects=True,
    )
    check("Password changed", "password has been changed" in response.get_data(as_text=True))
    check("Current device stays signed in", client.get("/my-information").status_code == 200)

    response = second_device.get("/my-information")
    check(
        "Other device signed out by password change",
        response.status_code == 302 and "/sign-in" in response.headers.get("Location", ""),
        f"got {response.status_code}",
    )

    check("Old password no longer works", "Incorrect username or password" in sign_in(app.test_client(), "sam.okafor", GOOD_PASSWORD).get_data(as_text=True))
    check("New password works", "Signed in as" in sign_in(app.test_client(), "sam.okafor", NEW_PASSWORD).get_data(as_text=True))

    print("\nAccount lockout")
    clear_limits()
    locker = app.test_client()
    register(locker, "lockme", "lockme@example.com", GOOD_PASSWORD)
    locker.post("/sign-out", data={"csrf_token": token_for(locker, "/")}, follow_redirects=True)
    for _ in range(5):
        sign_in(locker, "lockme", "definitely-wrong-here")
    response = sign_in(locker, "lockme", GOOD_PASSWORD)
    check(
        "Account locks after repeated failures",
        "Too many failed attempts" in response.get_data(as_text=True),
    )
    with app.app_context():
        locked = db.session.scalar(db.select(User).filter_by(username_lookup=_bi(app, "lockme")))
        check("Lockout is time-limited, not permanent", locked.is_locked and locked.lockout_seconds_remaining() <= 30 * 60)

    print("\nPassword reset")
    clear_limits()
    with app.app_context():
        target = db.session.scalar(db.select(User).filter_by(username_lookup=_bi(app, "lockme")))
        target_id = target.id

    resetter = app.test_client()
    response = resetter.post(
        "/forgot-password",
        data={"csrf_token": token_for(resetter, "/forgot-password"), "email": "lockme@example.com"},
        follow_redirects=True,
    )
    check("Reset request accepted", response.status_code == 200)

    unknown = app.test_client()
    known_body = response.get_data(as_text=True)
    response = unknown.post(
        "/forgot-password",
        data={"csrf_token": token_for(unknown, "/forgot-password"), "email": "nobody@example.com"},
        follow_redirects=True,
    )
    check(
        "Unknown email gives identical response",
        response.get_data(as_text=True) == known_body,
    )
    with app.app_context():
        issued = db.session.scalar(db.select(db.func.count()).select_from(PasswordResetToken))
    check("No token issued for unknown email", issued == 1, f"{issued} tokens")

    # Recover the raw token the way the email would carry it.
    from app.security import hash_token, new_token

    raw_token = new_token()
    with app.app_context():
        record = db.session.scalar(db.select(PasswordResetToken).filter_by(user_id=target_id))
        record.token_hash = hash_token(raw_token)
        db.session.commit()
        check("Only the token hash is stored", raw_token not in record.token_hash)

    check("Bad token refused", resetter.get("/reset-password/not-a-real-token").status_code == 302)
    check("Valid token opens the form", resetter.get(f"/reset-password/{raw_token}").status_code == 200)

    reset_password = "driftwood-marmalade-88"
    response = resetter.post(
        f"/reset-password/{raw_token}",
        data={
            "csrf_token": token_for(resetter, f"/reset-password/{raw_token}"),
            "new_password": reset_password,
            "new_password_confirm": reset_password,
        },
        follow_redirects=True,
    )
    check("Password reset succeeded", "password has been reset" in response.get_data(as_text=True))
    check(
        "Token is single-use",
        resetter.get(f"/reset-password/{raw_token}").status_code == 302,
    )
    check(
        "Reset clears the lockout",
        "Signed in as" in sign_in(app.test_client(), "lockme", reset_password).get_data(as_text=True),
    )

    print("\nTag requests")
    clear_limits()

    # Signed out: the standalone page explains why an account is needed, and
    # the form is not there to submit.
    stranger = app.test_client()
    response = stranger.get("/request-a-tag")
    check("Signed-out visitor sees the explainer", response.status_code == 200)
    body = response.get_data(as_text=True)
    check("Explainer asks them to register", "Create an account" in body)
    check("Explainer carries no address field", 'name="postal_address"' not in body)
    check(
        "Signed-out submission is refused",
        stranger.post(
            "/my-information/request-a-tag",
            data={"csrf_token": token_for(stranger, "/sign-in"), "postal_address": "nowhere"},
        ).status_code
        in (302, 400),
    )

    # Signed in: /request-a-tag hands off to the form on the record page.
    response = client.get("/request-a-tag")
    check(
        "Signed-in visitor is sent to the record page",
        response.status_code == 302 and "/my-information" in response.headers.get("Location", ""),
        f"got {response.status_code}",
    )

    response = client.get("/my-information")
    body = response.get_data(as_text=True)
    check("Record page carries the tag form", 'id="request-a-tag"' in body)
    check("Form asks for a delivery address", 'name="postal_address"' in body)
    check("Form offers the QR option", 'name="wants_qr"' in body)
    check("Form no longer asks for a name", 'name="full_name"' not in body)
    check("Form no longer asks for an email", 'name="email"' not in body)
    check("Form no longer asks for a phone", 'name="phone"' not in body)

    # A dedicated account, so this does not leave the sam.okafor account (used
    # heavily below, including in the "no card exists yet" assertions further
    # down) holding a card it did not ask for.
    requester = app.test_client()
    register(requester, "requester", "requester@example.com", GOOD_PASSWORD)
    response = requester.post(
        "/my-information/request-a-tag",
        data={
            "csrf_token": token_for(requester, "/my-information"),
            "postal_address": "9 Dock Lane\nGlasgow\nG1 1AA",
            "tag_style": "Wallet card",
            "wants_qr": "yes",
        },
        follow_redirects=True,
    )
    check("Tag request accepted", response.status_code == 200)
    check("Confirmation is shown in place", "has been sent" in response.get_data(as_text=True))

    with app.app_context():
        signed_in_request = db.session.scalar(
            db.select(TagRequest).filter(TagRequest.user_id.is_not(None))
        )
        signed_in_request_id = signed_in_request.id
        check("Request is linked to the account", signed_in_request.user_id is not None)
        check("QR preference stored", signed_in_request.wants_qr is True)
        check(
            "Name and email read through to the account",
            signed_in_request.contact_name == "requester"
            and signed_in_request.contact_email == "requester@example.com",
        )
        raw_tag = db.session.execute(db.text("SELECT postal_address FROM tag_requests")).first()
        check("Tag address encrypted at rest", "Dock Lane" not in str(raw_tag[0]))

    # Unticking the box has to actually persist as False, not silently default.
    noqr = app.test_client()
    register(noqr, "noqr", "noqr@example.com", GOOD_PASSWORD)
    noqr.post(
        "/my-information/request-a-tag",
        data={
            "csrf_token": token_for(noqr, "/my-information"),
            "postal_address": "1 Plain Street\nDundee\nDD1 1AA",
        },
        follow_redirects=True,
    )
    with app.app_context():
        noqr_user_id = db.session.scalar(
            db.select(User.id).filter_by(username_lookup=_bi(app, "noqr"))
        )
        noqr_request = db.session.scalar(
            db.select(TagRequest).filter_by(user_id=noqr_user_id)
        )
        check("Unticked QR box stores False", noqr_request is not None and noqr_request.wants_qr is False)

    # An address is the only required field now.
    blank = app.test_client()
    register(blank, "blankaddr", "blankaddr@example.com", GOOD_PASSWORD)
    response = blank.post(
        "/my-information/request-a-tag",
        data={"csrf_token": token_for(blank, "/my-information"), "postal_address": "  "},
        follow_redirects=True,
    )
    check(
        "Missing address is rejected",
        "address we can post the tag to" in response.get_data(as_text=True),
    )

    print("\nAdmin gating")
    clear_limits()
    check("Non-admin gets 404", client.get("/admin/tag-requests").status_code == 404)
    host = app.test_client()
    register(host, "thehost", "host@example.com", GOOD_PASSWORD)
    response = host.get("/admin/tag-requests")
    check("Admin can read requests", response.status_code == 200, f"got {response.status_code}")
    check("Admin sees decrypted request", "9 Dock Lane" in response.get_data(as_text=True))
    check("Admin sees the account behind the request", "requester" in response.get_data(as_text=True))
    check("Admin sees the QR preference", "printed QR" in response.get_data(as_text=True))
    check("Reveal button offered for a signed-in request", "Reveal link" in response.get_data(as_text=True))

    print("\nAdmin fulfilment: revealing an emergency link")
    with app.app_context():
        owner_id = db.session.get(TagRequest, signed_in_request_id).user_id
        had_card_before = db.session.scalar(
            db.select(db.func.count()).select_from(EmergencyCard).filter_by(user_id=owner_id)
        )
    check("No card existed yet for this account", had_card_before == 0, f"{had_card_before} cards")

    response = host.post(
        f"/admin/tag-requests/{signed_in_request_id}/reveal-emergency-link",
        data={"csrf_token": token_for(host, "/admin/tag-requests")},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    check("Reveal succeeds", response.status_code == 200, f"got {response.status_code}")
    check("Flash contains an emergency URL", "/e/" in body)

    with app.app_context():
        revealed_card = db.session.scalar(db.select(EmergencyCard).filter_by(user_id=owner_id))
        check("A card was created on the owner's behalf", revealed_card is not None)
        check(
            "Revealed token appears in the flashed URL",
            revealed_card is not None and revealed_card.token in body,
        )
        entry = db.session.scalar(
            db.select(EmergencyAccess).filter_by(
                card_id=revealed_card.id, source=EmergencyAccess.SOURCE_ADMIN_REVEAL
            )
        )
        check("Reveal was logged with the admin_reveal source", entry is not None)

    response = requester.get("/my-information/emergency")
    check(
        "Owner sees the admin reveal in their own log",
        "Opened by the site host" in response.get_data(as_text=True),
    )

    non_admin_signup = app.test_client()
    register(non_admin_signup, "notthehost", "notthehost@example.com", GOOD_PASSWORD)
    check(
        "Non-admin cannot reveal",
        non_admin_signup.post(
            f"/admin/tag-requests/{signed_in_request_id}/reveal-emergency-link",
            data={"csrf_token": token_for(non_admin_signup, "/")},
        ).status_code
        in (302, 404),
    )

    # The form now requires sign-in, so an unlinked request can no longer be
    # created through the site -- but rows from before that change still exist
    # in production, and the guard against revealing them has to keep working.
    with app.app_context():
        legacy = TagRequest(
            user_id=None,
            full_name="Legacy Requester",
            email="legacy@example.com",
            postal_address="4 Old Road\nAberdeen\nAB1 1AA",
        )
        db.session.add(legacy)
        db.session.commit()
        anon_request_id = legacy.id
        cards_before = db.session.scalar(
            db.select(db.func.count()).select_from(EmergencyCard)
        )

    response = host.post(
        f"/admin/tag-requests/{anon_request_id}/reveal-emergency-link",
        data={"csrf_token": token_for(host, "/admin/tag-requests")},
        follow_redirects=True,
    )
    check(
        "Legacy unlinked request cannot be revealed",
        "not submitted while signed in" in response.get_data(as_text=True),
    )
    check(
        "Legacy request still shows its typed-in name",
        "Legacy Requester" in host.get("/admin/tag-requests").get_data(as_text=True),
    )
    with app.app_context():
        cards_after = db.session.scalar(
            db.select(db.func.count()).select_from(EmergencyCard)
        )
    check(
        "No card was created for the unlinked request",
        cards_after == cards_before,
        f"{cards_before} -> {cards_after}",
    )

    print("\nEmergency links directory")
    clear_limits()
    check(
        "Non-admin cannot reach the directory",
        non_admin_signup.get("/admin/emergency-links").status_code == 404,
    )
    response = host.get("/admin/emergency-links")
    check("Admin can open the directory", response.status_code == 200)
    body = response.get_data(as_text=True)
    check("Directory lists a registered account", "requester" in body)
    check("Directory shows field count, not values", "field" in body.lower())
    check("Directory never shows a token itself", "/e/" not in body)

    response = host.get("/admin/emergency-links?q=requester")
    check("Exact-username search finds the account", "requester" in response.get_data(as_text=True))

    response = host.get("/admin/emergency-links?q=requester@example.com")
    check("Exact-email search finds the same account", "requester" in response.get_data(as_text=True))

    response = host.get("/admin/emergency-links?q=nobody-by-this-name")
    check("Search with no match finds nothing", "requester" not in response.get_data(as_text=True))

    with app.app_context():
        requester_id = db.session.scalar(
            db.select(User.id).filter_by(username_lookup=_bi(app, "requester"))
        )
        existing_card_before = db.session.scalar(
            db.select(EmergencyCard).filter_by(user_id=requester_id)
        )
        existing_token = existing_card_before.token
        access_count_before = db.session.scalar(
            db.select(db.func.count()).select_from(EmergencyAccess).filter_by(card_id=existing_card_before.id)
        )

    response = host.post(
        f"/admin/emergency-links/{requester_id}/reveal",
        data={"csrf_token": token_for(host, "/admin/emergency-links")},
        follow_redirects=True,
    )
    check("Directory reveal succeeds", response.status_code == 200)
    check(
        "Directory reveal returns the same existing token, not a new one",
        existing_token in response.get_data(as_text=True),
    )
    with app.app_context():
        access_count_after = db.session.scalar(
            db.select(db.func.count()).select_from(EmergencyAccess).filter_by(card_id=existing_card_before.id)
        )
    check(
        "Directory reveal is logged too",
        access_count_after == access_count_before + 1,
        f"{access_count_before} -> {access_count_after}",
    )

    response = requester.get("/my-information/emergency")
    check(
        "Second reveal also shows up in the owner's own log",
        response.get_data(as_text=True).count("Opened by the site host") >= 2,
    )

    check(
        "Non-admin cannot POST a reveal directly",
        non_admin_signup.post(
            f"/admin/emergency-links/{requester_id}/reveal",
            data={"csrf_token": token_for(non_admin_signup, "/")},
        ).status_code
        in (302, 404),
    )

    print("\nAccount deletion")
    clear_limits()
    doomed = app.test_client()
    register(doomed, "deleteme", "deleteme@example.com", GOOD_PASSWORD)
    doomed.post(
        "/my-details",
        data={"csrf_token": token_for(doomed, "/my-details"), "full_name": "Delete Me"},
        follow_redirects=True,
    )
    with app.app_context():
        doomed_user = db.session.scalar(db.select(User).filter_by(username_lookup=_bi(app, "deleteme")))
        doomed_id = doomed_user.id

    response = doomed.post(
        "/account/delete",
        data={"csrf_token": token_for(doomed, "/account"), "password": "wrong-password-here"},
        follow_redirects=True,
    )
    check("Deletion needs the right password", "enter your current password" in response.get_data(as_text=True))

    response = doomed.post(
        "/account/delete",
        data={"csrf_token": token_for(doomed, "/account"), "password": GOOD_PASSWORD},
        follow_redirects=True,
    )
    check("Account deleted", "have been deleted" in response.get_data(as_text=True))
    with app.app_context():
        check("User row gone", db.session.get(User, doomed_id) is None)
        orphans = db.session.scalar(
            db.select(db.func.count()).select_from(EpilepsyProfile).filter_by(user_id=doomed_id)
        )
        check("Record cascade-deleted", orphans == 0, f"{orphans} rows")

    print("\nEmergency tag (NFC)")
    clear_limits()
    scanner = app.test_client()  # nobody: never signed in

    check("No card yet", client.get("/my-information/emergency").status_code == 200)
    check(
        "QR 404s before a card exists",
        client.get("/my-information/emergency/qr.svg").status_code == 404,
    )

    response = client.post(
        "/my-information/emergency/create",
        data={"csrf_token": token_for(client, "/my-information/emergency")},
        follow_redirects=True,
    )
    check("Card created", "ready to write to a tag" in response.get_data(as_text=True))

    with app.app_context():
        sam_id = db.session.scalar(
            db.select(User.id).filter_by(username_lookup=_bi(app, "sam.okafor"))
        )
        card = db.session.scalar(db.select(EmergencyCard).filter_by(user_id=sam_id))
        card_token = card.token
        card_id = card.id
    check("Token is 128-bit URL-safe", len(card_token) == 22, f"{len(card_token)} chars")

    with app.app_context():
        raw = db.session.execute(db.text("SELECT token FROM emergency_cards")).scalar()
        check("Token encrypted at rest", card_token not in str(raw))
        check("Stored token is Fernet ciphertext", str(raw).startswith("gAAAAA"))

    # The whole point: a stranger with the link, and no account.
    response = scanner.get(f"/e/{card_token}")
    check("Anonymous scan succeeds", response.status_code == 200, f"got {response.status_code}")
    body = response.get_data(as_text=True)
    check("Card shows the medication", "Lamotrigine 200mg twice daily" in body)
    check("Card shows first aid", "Cushion my head" in body)
    check("Card shows the emergency contact", "Ada Okafor" in body)
    check("Urgent section ordered first", body.index("Read this first") < body.index("Medical background"))
    check("Phone numbers become tel: links", 'href="tel:07700900456"' in body)
    check("Card carries no site navigation", "Create account" not in body)

    print("\nEmergency tag leak protection")
    check("No referrer sent onward", response.headers.get("Referrer-Policy") == "no-referrer")
    check("Never cached", "no-store" in response.headers.get("Cache-Control", ""))
    check("Excluded from search engines", "noindex" in response.headers.get("X-Robots-Tag", ""))
    check("Meta robots tag present", 'name="robots"' in body and "noindex" in body)
    robots = scanner.get("/robots.txt")
    check("robots.txt disallows /e/", "Disallow: /e/" in robots.get_data(as_text=True))

    print("\nEmergency tag access control")
    check("Wrong token 404s", scanner.get("/e/" + "A" * 22).status_code == 404)
    check(
        "Wrong token still gives first aid",
        "seizure" in scanner.get("/e/" + "B" * 22).get_data(as_text=True).lower(),
    )
    check(
        "Another user cannot reach the management page for this card",
        app.test_client().get("/my-information/emergency").status_code == 302,
    )

    # A second account must get its own card, never this one.
    neighbour = app.test_client()
    register(neighbour, "neighbour", "neighbour@example.com", GOOD_PASSWORD)
    neighbour.post(
        "/my-information/emergency/create",
        data={"csrf_token": token_for(neighbour, "/my-information/emergency")},
        follow_redirects=True,
    )
    with app.app_context():
        neighbour_id = db.session.scalar(
            db.select(User.id).filter_by(username_lookup=_bi(app, "neighbour"))
        )
        neighbour_token = db.session.scalar(
            db.select(EmergencyCard.token).filter_by(user_id=neighbour_id)
        )
    check("Each account gets a distinct token", neighbour_token != card_token)
    check(
        "Neighbour's card does not show my data",
        "Lamotrigine" not in scanner.get(f"/e/{neighbour_token}").get_data(as_text=True),
    )

    print("\nEmergency tag lifecycle")
    with app.app_context():
        logged = db.session.scalar(
            db.select(db.func.count()).select_from(EmergencyAccess).filter_by(card_id=card_id)
        )
    check("Scans are logged for the owner", logged >= 1, f"{logged} entries")
    with app.app_context():
        source = db.session.execute(
            db.text("SELECT source_hash FROM emergency_accesses LIMIT 1")
        ).scalar()
        check("Viewer address stored only as a hash", source and "127.0.0.1" not in str(source))

    client.post(
        "/my-information/emergency/toggle",
        data={"csrf_token": token_for(client, "/my-information/emergency")},
        follow_redirects=True,
    )
    response = scanner.get(f"/e/{card_token}")
    check("Switched-off tag stops showing data", response.status_code == 410, f"got {response.status_code}")
    check("Switched-off tag hides the record", "Lamotrigine" not in response.get_data(as_text=True))
    check(
        "Switched-off tag still gives first aid",
        "seizure" in response.get_data(as_text=True).lower(),
    )

    client.post(
        "/my-information/emergency/toggle",
        data={"csrf_token": token_for(client, "/my-information/emergency")},
        follow_redirects=True,
    )
    check("Toggling back on restores it", scanner.get(f"/e/{card_token}").status_code == 200)

    client.post(
        "/my-information/emergency/regenerate",
        data={"csrf_token": token_for(client, "/my-information/emergency")},
        follow_redirects=True,
    )
    check("Retired token stops working", scanner.get(f"/e/{card_token}").status_code == 404)
    with app.app_context():
        fresh = db.session.get(EmergencyCard, card_id)
        check("A different token was issued", fresh.token != card_token)
        check("Old access log was cleared with it", len(fresh.accesses) == 0)
        new_token_value = fresh.token
    check("New token works", scanner.get(f"/e/{new_token_value}").status_code == 200)

    print("\nQR fallback")
    response = client.get("/my-information/emergency/qr.svg")
    check("QR renders", response.status_code == 200, f"got {response.status_code}")
    check("QR is an SVG", response.mimetype == "image/svg+xml", response.mimetype)
    check("QR is not cached", "no-store" in response.headers.get("Cache-Control", ""))

    print("\nEmergency token brute force")
    clear_limits()
    blocked = False
    for index in range(25):
        if scanner.get(f"/e/wrongtoken{index:012d}").status_code == 429:
            blocked = True
            break
    check("Guessing is rate limited", blocked)
    check(
        "A real scan still works while guessers are blocked",
        scanner.get(f"/e/{new_token_value}").status_code == 200,
    )

    print("\nRate limiting")
    clear_limits()
    limited = False
    hammer = app.test_client()
    for _ in range(14):
        response = hammer.post(
            "/sign-in",
            data={
                "csrf_token": token_for(hammer, "/sign-in"),
                "username": "sam.okafor",
                "password": "wrong-every-time",
            },
        )
        if response.status_code == 429:
            limited = True
            break
    check("Sign-in rate limit trips", limited)

    print("\nOpen redirect protection")
    from app.views.auth import _safe_next

    with app.test_request_context():
        check("External next rejected", _safe_next("https://evil.example") == "/my-information")
        check("Protocol-relative next rejected", _safe_next("//evil.example") == "/my-information")
        check("Internal next allowed", _safe_next("/my-details") == "/my-details")

    print("\n" + "=" * 58)
    print(f"  {len(PASSED)} passed, {len(FAILED)} failed")
    if FAILED:
        for name, detail in FAILED:
            print(f"    - {name} {detail}")
    print("=" * 58)
    return 1 if FAILED else 0


def _bi(app, value: str) -> str:
    from app.security import blind_index

    with app.app_context():
        return blind_index(value)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
