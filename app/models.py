"""Database models.

Anything that is health information, or that identifies a person, is stored in
an :class:`~app.security.EncryptedText` column. Only opaque identifiers,
timestamps and workflow status live in plaintext.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .extensions import db
from .security import EncryptedText

# Progressive lockout after this many consecutive failures. A hard permanent
# lock would let anyone deny a real person access to their own medical record
# just by guessing wrong at them repeatedly, so the delay grows instead.
LOCKOUT_THRESHOLD = 5
LOCKOUT_MAX_MINUTES = 30


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Encrypted, because on a site about epilepsy the mere fact that an address
    # holds an account is a health inference. The *_lookup columns are keyed
    # HMACs of the casefolded value: searchable, unique, and useless to anyone
    # who steals the database without also stealing BLIND_INDEX_KEY.
    username_lookup: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    username: Mapped[str] = mapped_column(EncryptedText)

    email_lookup: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(EncryptedText)

    # Argon2id output. Already one-way, so it is not additionally encrypted --
    # doing so would add no security and would break rehash-on-login.
    password_hash: Mapped[str] = mapped_column(sa.String(255))
    password_changed_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=_utcnow
    )

    # Bumped on password change or reset. Any session carrying an older value is
    # discarded, so changing your password really does sign out other devices.
    session_epoch: Mapped[int] = mapped_column(sa.Integer, default=0)

    failed_login_count: Mapped[int] = mapped_column(sa.Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    profile: Mapped["EpilepsyProfile | None"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    tag_requests: Mapped[list["TagRequest"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    reset_tokens: Mapped[list["PasswordResetToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    emergency_card: Mapped["EmergencyCard | None"] = relationship(
        back_populates="user", uselist=False, cascade="all, delete-orphan"
    )

    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        locked_until = self.locked_until
        if locked_until.tzinfo is None:  # SQLite hands back naive datetimes
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return locked_until > _utcnow()

    def lockout_seconds_remaining(self) -> int:
        if not self.is_locked:
            return 0
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return max(0, int((locked_until - _utcnow()).total_seconds()))

    def register_failed_login(self) -> None:
        self.failed_login_count = (self.failed_login_count or 0) + 1
        if self.failed_login_count >= LOCKOUT_THRESHOLD:
            over = self.failed_login_count - LOCKOUT_THRESHOLD
            minutes = min(2**over, LOCKOUT_MAX_MINUTES)
            self.locked_until = _utcnow() + timedelta(minutes=minutes)

    def register_successful_login(self) -> None:
        self.failed_login_count = 0
        self.locked_until = None
        self.last_login_at = _utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.id}>"


class PasswordResetToken(db.Model):
    """A single-use, time-limited password reset.

    Only the hash of the token is stored, so a stolen database yields nothing
    that can be redeemed. The raw token exists solely inside the email.
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)

    user: Mapped[User] = relationship(back_populates="reset_tokens")

    @property
    def is_usable(self) -> bool:
        if self.used_at is not None:
            return False
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at > _utcnow()


class EpilepsyProfile(db.Model):
    """One record per user, holding their own account of their epilepsy.

    Every field is optional. People are told this information in fragments over
    years, and a half-filled record is still worth carrying.
    """

    __tablename__ = "epilepsy_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True
    )

    # --- Identity -----------------------------------------------------
    full_name: Mapped[str | None] = mapped_column(EncryptedText)
    date_of_birth: Mapped[str | None] = mapped_column(EncryptedText)
    blood_type: Mapped[str | None] = mapped_column(EncryptedText)

    # --- The seizures themselves --------------------------------------
    diagnosis: Mapped[str | None] = mapped_column(EncryptedText)
    seizure_types: Mapped[str | None] = mapped_column(EncryptedText)
    seizure_description: Mapped[str | None] = mapped_column(EncryptedText)
    typical_duration: Mapped[str | None] = mapped_column(EncryptedText)
    frequency: Mapped[str | None] = mapped_column(EncryptedText)
    warning_signs: Mapped[str | None] = mapped_column(EncryptedText)
    triggers: Mapped[str | None] = mapped_column(EncryptedText)
    recovery_notes: Mapped[str | None] = mapped_column(EncryptedText)

    # --- What a bystander should do ------------------------------------
    first_aid_notes: Mapped[str | None] = mapped_column(EncryptedText)
    do_not_do: Mapped[str | None] = mapped_column(EncryptedText)
    call_ambulance_if: Mapped[str | None] = mapped_column(EncryptedText)

    # --- Treatment ------------------------------------------------------
    medications: Mapped[str | None] = mapped_column(EncryptedText)
    rescue_medication: Mapped[str | None] = mapped_column(EncryptedText)
    allergies: Mapped[str | None] = mapped_column(EncryptedText)
    implanted_device: Mapped[str | None] = mapped_column(EncryptedText)
    other_conditions: Mapped[str | None] = mapped_column(EncryptedText)

    # --- People to reach -------------------------------------------------
    emergency_contact_1: Mapped[str | None] = mapped_column(EncryptedText)
    emergency_contact_2: Mapped[str | None] = mapped_column(EncryptedText)
    clinician: Mapped[str | None] = mapped_column(EncryptedText)

    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    user: Mapped[User] = relationship(back_populates="profile")

    # Field order here drives both the editor and the read-only card, so the two
    # pages can never drift apart.
    SECTIONS: tuple[tuple[str, str, tuple[tuple[str, str, str, str], ...]], ...] = (
        (
            "About me",
            "Who this record belongs to.",
            (
                ("full_name", "Full name", "text", "The name you want responders to use."),
                ("date_of_birth", "Date of birth", "text", "e.g. 14 March 1996"),
                ("blood_type", "Blood type", "text", "Only if you know it."),
            ),
        ),
        (
            "My seizures",
            "What happens, and what it looks like from the outside.",
            (
                ("diagnosis", "Diagnosis", "text", "e.g. Focal epilepsy, temporal lobe"),
                ("seizure_types", "Seizure types", "text", "e.g. Focal aware, tonic-clonic"),
                (
                    "seizure_description",
                    "What a seizure looks like",
                    "textarea",
                    "Describe it the way you would to someone who has never seen one.",
                ),
                ("typical_duration", "Typical duration", "text", "e.g. 1-2 minutes"),
                ("frequency", "How often", "text", "e.g. Two or three a month"),
                (
                    "warning_signs",
                    "Warning signs or aura",
                    "textarea",
                    "Anything you notice beforehand.",
                ),
                ("triggers", "Known triggers", "textarea", "e.g. Missed sleep, illness, stress"),
                (
                    "recovery_notes",
                    "Afterwards",
                    "textarea",
                    "How long recovery takes and what helps.",
                ),
            ),
        ),
        (
            "If you are helping me",
            "Instructions for whoever is with you when it happens.",
            (
                ("first_aid_notes", "Please do this", "textarea", "e.g. Time it. Cushion my head."),
                ("do_not_do", "Please do not do this", "textarea", "e.g. Do not restrain me."),
                (
                    "call_ambulance_if",
                    "Call an ambulance if",
                    "textarea",
                    "e.g. The seizure passes five minutes, or a second one follows.",
                ),
            ),
        ),
        (
            "Treatment",
            "Medication and anything implanted.",
            (
                ("medications", "Daily medication", "textarea", "Name, dose and timing."),
                (
                    "rescue_medication",
                    "Rescue medication",
                    "textarea",
                    "What it is, where it is kept, and when to give it.",
                ),
                ("allergies", "Allergies", "textarea", "Medication and other allergies."),
                (
                    "implanted_device",
                    "Implanted device",
                    "text",
                    "e.g. VNS fitted 2022 - magnet in my bag",
                ),
                ("other_conditions", "Other conditions", "textarea", ""),
            ),
        ),
        (
            "Who to contact",
            "The people who should hear about it.",
            (
                (
                    "emergency_contact_1",
                    "Emergency contact",
                    "textarea",
                    "Name, relationship and phone number.",
                ),
                ("emergency_contact_2", "Second contact", "textarea", ""),
                ("clinician", "Neurologist or GP", "textarea", "Name, clinic and phone number."),
            ),
        ),
    )

    # The emergency card reorders the same fields for someone who has thirty
    # seconds and a person on the floor in front of them. An implanted VNS
    # device and a drug allergy change what a responder does *first*, so they
    # lead; the person's history matters, but it can wait three lines.
    EMERGENCY_LAYOUT: tuple[tuple[str, tuple[str, ...]], ...] = (
        (
            "Read this first",
            ("implanted_device", "allergies", "rescue_medication"),
        ),
        (
            "If they are having a seizure now",
            ("first_aid_notes", "do_not_do", "call_ambulance_if"),
        ),
        (
            "What their seizures look like",
            (
                "seizure_types",
                "seizure_description",
                "typical_duration",
                "warning_signs",
                "recovery_notes",
                "triggers",
                "frequency",
            ),
        ),
        (
            "Medical background",
            ("diagnosis", "medications", "other_conditions", "blood_type"),
        ),
        (
            "Who to contact",
            ("emergency_contact_1", "emergency_contact_2", "clinician"),
        ),
    )

    # Shown in the card header rather than as a labelled row.
    EMERGENCY_HEADER_FIELDS: tuple[str, ...] = ("full_name", "date_of_birth")

    @classmethod
    def field_names(cls) -> list[str]:
        return [f[0] for section in cls.SECTIONS for f in section[2]]

    @classmethod
    def labels(cls) -> dict[str, str]:
        return {f[0]: f[1] for section in cls.SECTIONS for f in section[2]}

    def emergency_sections(self) -> list[tuple[str, list[tuple[str, str]]]]:
        """(heading, [(label, value)]) for every field this person filled in."""
        labels = self.labels()
        out: list[tuple[str, list[tuple[str, str]]]] = []
        for heading, names in self.EMERGENCY_LAYOUT:
            rows = [
                (labels[name], getattr(self, name))
                for name in names
                if (getattr(self, name) or "").strip()
            ]
            if rows:
                out.append((heading, rows))
        return out

    def is_empty(self) -> bool:
        return not any((getattr(self, name) or "").strip() for name in self.field_names())

    def completed_count(self) -> int:
        return sum(1 for name in self.field_names() if (getattr(self, name) or "").strip())


class EmergencyCard(db.Model):
    """The thing an NFC tag points at.

    A paramedic has no account here, so possession of the physical tag has to be
    the authorisation: the token in the URL *is* the permission. That makes two
    properties non-negotiable.

    First, the token must be unguessable -- 128 bits of randomness, so sweeping
    the URL space is not a strategy. Second, it must not leak: the page carrying
    it sends no referrer, is never cached, and is excluded from search engines.

    The token is stored encrypted rather than hashed. Hashing would be stronger,
    but the tag is a physical object programmed once -- the owner has to be able
    to read the URL back to write a replacement tag or print a card, and forcing
    a regeneration every time would strand every tag already in a wallet.
    """

    __tablename__ = "emergency_cards"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        sa.ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True
    )

    token_lookup: Mapped[str] = mapped_column(sa.String(64), unique=True, index=True)
    token: Mapped[str] = mapped_column(EncryptedText)

    # Lets someone switch the tag off without destroying it -- during a hospital
    # stay, or if a bag goes missing and they want to think before regenerating.
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    regenerated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="emergency_card")
    accesses: Mapped[list["EmergencyAccess"]] = relationship(
        back_populates="card",
        cascade="all, delete-orphan",
        order_by="EmergencyAccess.accessed_at.desc()",
    )


class EmergencyAccess(db.Model):
    """A record that someone opened the card, so the owner can see it happening.

    The viewer's address is stored only as a keyed hash. That is enough to tell
    one scanner apart from another in the owner's log, without this site keeping
    a list of the IP addresses of people who have helped them.
    """

    __tablename__ = "emergency_accesses"

    # Older rows are pruned beyond this many per card, so a tag left on a desk
    # cannot grow the table without bound.
    RETAIN_PER_CARD = 50

    id: Mapped[int] = mapped_column(primary_key=True)
    card_id: Mapped[int] = mapped_column(
        sa.ForeignKey("emergency_cards.id", ondelete="CASCADE"), index=True
    )
    accessed_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)
    source_hash: Mapped[str | None] = mapped_column(sa.String(64))

    card: Mapped[EmergencyCard] = relationship(back_populates="accesses")


class TagRequest(db.Model):
    """A request to the site host for a physical epilepsy tag."""

    __tablename__ = "tag_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    full_name: Mapped[str | None] = mapped_column(EncryptedText)
    email: Mapped[str | None] = mapped_column(EncryptedText)
    phone: Mapped[str | None] = mapped_column(EncryptedText)
    postal_address: Mapped[str | None] = mapped_column(EncryptedText)
    tag_style: Mapped[str | None] = mapped_column(EncryptedText)
    engraving: Mapped[str | None] = mapped_column(EncryptedText)
    message: Mapped[str | None] = mapped_column(EncryptedText)

    status: Mapped[str] = mapped_column(sa.String(32), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), default=_utcnow)

    user: Mapped[User | None] = relationship(back_populates="tag_requests")
