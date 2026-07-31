# Seizure66

An epilepsy awareness site with a private, encrypted place for people to keep
the information that matters when they cannot explain it themselves.

- **Awareness** — what epilepsy is, what seizures actually look like, and
  seizure first aid ("Stay. Safe. Side.").
- **Request a tag** — a form that sends a request to the site host for a
  physical epilepsy tag (bracelet, necklace, shoe tag, wallet card).
- **Your record** — create an account and store seizure types, triggers,
  warning signs, first-aid instructions, medication and emergency contacts.
- **`/my-information`** — a separate, read-only page showing nothing but the
  signed-in user's own information. Print-friendly, and downloadable.
- **Emergency tag** — an NFC tag (or printed QR code) that shows a responder the
  wearer's epilepsy information with no sign-in, at the moment they cannot
  explain it themselves.

## Design note: nothing on this site flashes

Three to five percent of people with epilepsy are photosensitive. There is no
keyframe animation, no strobing, no autoplaying media, and no transition faster
than 150ms anywhere in the stylesheet, and `prefers-reduced-motion` disables
even those. Please keep it that way when extending the site.

---

## The emergency tag

A paramedic has no account here and no time to make one. So possession of the
physical tag *is* the authorisation: the NFC tag holds a URL like
`https://your-app.onrender.com/e/XrkeTu3VGRlA9_L3Ae1ywA`, and anyone who scans it
sees the wearer's information immediately, signed in or not.

That is a deliberate trade, and it is stated plainly to the user on the privacy
page rather than buried. A lock a stranger cannot open is useless in the
situation the tag exists for. What protects it instead:

| | |
|---|---|
| Guessing the address | 128 bits of randomness in a 22-character token. Not listed, linked, or published anywhere. |
| Leaking it via Referer | The page sends `Referrer-Policy: no-referrer` — stricter than the site default, which would still emit the origin. |
| Search engines | `X-Robots-Tag`, a `<meta name="robots">` tag, and `robots.txt`, independently. |
| Caching | `no-store, private` on every response. |
| Brute force | Only *failed* lookups are charged against a rate-limit budget. A valid scan is never rate limited — a responder must never be turned away because someone was probing the site an hour earlier. |
| A lost tag | The owner can switch it off instantly (reversible) or issue a new address that permanently retires the old one. |
| Not knowing it was used | Every view is logged for the owner. For an ordinary scan the viewer's IP is stored only as a keyed hash, so repeat scanners can be told apart without the site keeping a list of the people who helped them. |

The token is stored **encrypted rather than hashed** — the one place this project
does not hash a secret. A hash would be stronger, but the tag is a physical
object programmed once, and the owner has to read the URL back to write a
replacement or print a card. Hashing would strand every tag already in a wallet.

### The one deliberate exception: the site host can reveal any link

Everywhere else in the app, the token is invisible to everyone but its owner —
not even the site host has a route that shows it, and the medical fields stay
encrypted regardless. Fulfilling a physical tag breaks that, on purpose: if a
human is writing someone's link onto an NTAG before mailing it, that human
needs the exact URL, and there is no way around that once fulfilment is not the
owner printing their own QR code.

Two admin surfaces reveal a link, both going through the same logged path:

| Route | Scope |
|---|---|
| `/admin/tag-requests` → **Reveal link** | Requests submitted while signed in |
| `/admin/emergency-links` | Every registered account, searchable by exact username or email — for handing out a link with no shipping request open, e.g. replacing a lost tag in person |

What keeps either from being an open door:

- **Never bulk-visible.** No page lists tokens; each is revealed individually,
  one click at a time.
- **Never silent.** Every reveal writes an `EmergencyAccess` row with
  `source="admin_reveal"`, which shows up **in the owner's own access log** at
  `/my-information/emergency`, labelled "Opened by the site host" — the same
  list an ordinary scan appears in, not a private admin record the owner has no
  way to check.
- **Never the medical content.** The reveal surfaces the link, not the
  encrypted fields behind it — `/admin/emergency-links` shows only a field
  count (`12 of 23 filled in`), never a value.

This is a real, meaningful widening of who can reach one person's information
— from "nobody but the owner" to "the owner, or the site host on a logged,
deliberate action." It is stated plainly on the privacy page, not left
implicit: a user who does not want the site host to have this ability at all
should set up their own tag and print their own QR code, rather than using
"Request a tag".

### What a responder sees

`EpilepsyProfile.EMERGENCY_LAYOUT` reorders the same fields for someone with
thirty seconds and a person on the floor. An implanted VNS device and a drug
allergy change what they do *first*, so those lead; history can wait three lines.
Empty sections are omitted entirely. Phone numbers become `tel:` links so a
contact can be called with one tap — via a deliberately conservative pattern that
leaves dosages (`200mg`) and dates (`14 March 1996`) alone.

A scan of an unknown or switched-off tag still shows general seizure first aid,
rather than a bare error page. Someone is standing there either way.

### Writing a tag

Any NTAG213/NTAG215 sticker or wristband works, written as a URL record with an
app like NFC Tools. Step-by-step instructions are on the in-app page at
`/my-information/emergency`.

A **QR code** is generated alongside it (`segno`, dependency-free). NFC is not
universal — older handsets, a locked phone, a responder who does not think to
tap — and a printed QR beside the tag costs nothing and works anywhere a camera
does. This also makes the "wallet card" option in the tag request form
functional.

---

## How the data is protected

| Concern | Approach |
|---|---|
| Password cracking after a breach | **Argon2id** (`m=32768, t=3, p=1`), the Password Hashing Competition winner. Being memory-hard, it denies GPU and ASIC farms the speed advantage they get against bcrypt and PBKDF2. Each hash is individually salted, and re-hashed automatically on next sign-in if the parameters are later raised. |
| Weak passwords | 12-character minimum, a blocklist of the passwords that dominate breach corpora (including digit-padded variants like `password123456`), and rejection of passwords containing the username or email. No composition rules — per NIST SP 800-63B, mandatory symbols mostly produce `Password1!`. |
| Database dump or leaked backup | Every medical and personal field is encrypted with Fernet (AES-128-CBC + HMAC) **before** it reaches the database. Usernames and email addresses too: on an epilepsy site, the bare fact that an address has an account is a health inference. |
| Searching encrypted columns | A keyed HMAC-SHA256 **blind index** (`username_lookup`, `email_lookup`) alongside each ciphertext. Sign-in queries the index; because it is keyed, someone holding the database cannot hash a guessed username and look for a match. |
| Reading someone else's record | No route accepts a record ID. Every query is scoped by the signed-in `user_id`, so there is no object reference to tamper with. |
| Username enumeration | A wrong username and a wrong password return the same message, and take the same time — an unknown user is still verified against a dummy hash rather than returned early. The forgotten-password page responds identically whether or not the address is registered. |
| Credential stuffing | Progressive per-account lockout after 5 consecutive failures (doubling, capped at 30 minutes) plus per-IP rate limits. Deliberately not a permanent lock, which would let anyone deny a real person access to their own medical record. |
| Session theft | Cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` in production. The session is regenerated on sign-in to defeat fixation. Changing or resetting a password bumps a `session_epoch` that invalidates every other device. |
| Stolen reset links | Reset tokens are 256 bits of randomness, stored only as SHA-256 hashes, single-use, and expire in an hour. The database never holds a redeemable token. |
| Cross-site request forgery | `CSRFProtect` on every POST. |
| Injected scripts | A strict CSP with no `unsafe-inline`; no inline scripts or styles exist in the app. |
| Cached health data | Pages under `/my-information`, `/my-details`, `/account`, `/sign-in` and `/admin` are sent `Cache-Control: no-store, private`. |
| Form spam | Per-IP rolling-window rate limits, plus honeypot fields on the tag and registration forms. |
| Open redirect after sign-in | The `next` destination is validated to be a same-site path. |
| Emergency tag exposure | See [The emergency tag](#the-emergency-tag) above — capability URL, no referrer, no indexing, no caching, failure-only rate limiting, revocable. One deliberate, logged exception for physical fulfilment — see below. |
| Misconfigured production deploy | The app refuses to boot in production without `SECRET_KEY`, `FIELD_ENCRYPTION_KEYS` and `BLIND_INDEX_KEY`. |

Verify the encryption claims yourself — `smoke_test.py` reads the raw database
rows back with SQL and asserts that the password, the username, the email
address, the medication and the delivery address are all absent in plaintext.

> **Back up `FIELD_ENCRYPTION_KEYS`, and never change `BLIND_INDEX_KEY`.**
> Losing the first makes every stored record permanently unreadable. Changing
> the second changes every lookup value, and nobody will be able to sign in.
> Both are by design: there is no back door.

---

## Running it locally

```bash
py -3.13 -m venv .venv
```

```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

A `.env` has already been generated for local development, with a working
`SECRET_KEY`, `FIELD_ENCRYPTION_KEYS` and `BLIND_INDEX_KEY`. It is git-ignored.
Then:

```bash
.venv\Scripts\python.exe wsgi.py
```

The site runs at `http://localhost:5000` against a local SQLite file. Run the
test suite with:

```bash
.venv\Scripts\python.exe smoke_test.py
```

Sign-in works immediately — create an account at `/create-account`. Password
resets need SMTP; without it, the reset link is written to the server log in
development so you can still test the flow.

---

## Accounts

| Route | Purpose |
|---|---|
| `/create-account` | Register with a username, email and password |
| `/sign-in` | Sign in |
| `/account` | Change password, delete account |
| `/forgot-password` | Request a reset link |
| `/reset-password/<token>` | Set a new password |
| `/my-information` | Read-only view of your own record |
| `/my-information/emergency` | Set up and manage your NFC tag |
| `/e/<token>` | **Public.** What a scan of the tag shows |

**Email is required at registration, and it is the only recovery path.** Because
records are encrypted and passwords are only ever stored as hashes, an account
whose email address no longer works cannot be recovered by anyone, including
you. This is stated plainly on the privacy page.

### Configuring SMTP

Password resets are dead without it. Any provider works — for a Gmail account,
create an [App Password](https://myaccount.google.com/apppasswords) (this needs
2-Step Verification enabled) and use:

```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=your-16-character-app-password
SMTP_FROM=you@gmail.com
CONTACT_EMAIL=you@gmail.com
```

Never use your ordinary account password here.

---

## Deploying to Render

**See [DEPLOY.md](DEPLOY.md) for the full step-by-step with exact values.** The
short version follows.

### 1. Push to GitHub

```bash
git init && git add -A && git commit -m "Auraline: epilepsy awareness site"
```

Push that to a new GitHub repository. Confirm `.env` is **not** in the commit —
`.gitignore` covers it, but check.

### 2. Generate the production keys

Run each of these and keep the output somewhere safe and separate:

```bash
.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

```bash
.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

The first is `FIELD_ENCRYPTION_KEYS`, the second `BLIND_INDEX_KEY`. Use
**different** values from your local ones, so a local database and the
production database are never interchangeable.

### 3. Create the Blueprint

In Render: **New + → Blueprint**, point it at the repository. `render.yaml`
provisions a free Postgres database and a web service, and wires
`DATABASE_URL` and `SECRET_KEY` automatically.

### 4. Set the secrets Render cannot generate

In the service's **Environment** tab:

| Variable | Value |
|---|---|
| `FIELD_ENCRYPTION_KEYS` | The Fernet key from step 2 |
| `BLIND_INDEX_KEY` | The token from step 2 |
| `ADMIN_EMAILS` | The email you will register with, so you can read tag requests |
| `CONTACT_EMAIL` | Where tag requests are emailed |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` | SMTP details — without these, nobody can reset a password |

### 5. Register your own account

Visit `/create-account` on the deployed site and register with the address you
put in `ADMIN_EMAILS`. That unlocks `/admin/tag-requests` for you; everyone else
gets a 404 there.

### Notes on the free tier

- The free web service sleeps after inactivity; the first request afterwards
  takes 30–60 seconds.
- **Render's free Postgres databases expire after 30 days.** Upgrade the
  database before then, or the data is deleted. This matters more here than on
  a typical hobby project — people will be relying on this record.

---

## Tag requests

Submitted requests are stored encrypted and listed at **`/admin/tag-requests`**,
readable only by the accounts in `ADMIN_EMAILS` (anyone else gets a 404, so the
page's existence is not advertised). Each can be marked *new*, *in-progress*,
*sent* or *closed*.

If SMTP is configured, a notification is also emailed to `CONTACT_EMAIL` with
the visitor's address in `Reply-To`. Email is best-effort — a request is written
to the database before any mail is attempted, so an SMTP outage never loses one.

---

## Layout

```
app/
  __init__.py           application factory, request hooks, error handlers
  config.py             environment-driven configuration
  extensions.py         db / csrf singletons
  models.py             User, EpilepsyProfile, TagRequest, PasswordResetToken
  security.py           Argon2id hashing, EncryptedText, blind index,
                        password policy, rate limiting, guards, headers
  common_passwords.py   the blocklist
  mailer.py             tag request notifications, password reset emails
  views/
    main.py             awareness pages, tag requests, host inbox
    auth.py             register, sign in, change password, reset, delete
    records.py          read, edit, export, delete, manage the emergency tag
    emergency.py        the public /e/<token> scan page, robots.txt
  templates/
  static/
wsgi.py                 gunicorn entry point
render.yaml             Render Blueprint
smoke_test.py           127-check suite, no pytest needed
```

The fields on the record are defined once, in `EpilepsyProfile.SECTIONS`
([app/models.py](app/models.py)). Both the editor and the read-only page are
generated from it, so adding a field means editing one tuple — the two pages
cannot drift apart.

---

## Worth adding before a public launch

Two deliberate omissions, both reasonable to defer but worth knowing about:

- **Email verification at registration.** Nothing currently confirms the address
  someone typed is really theirs. A typo means an unrecoverable account, and it
  lets someone register under an address they do not own. The reset machinery in
  `views/auth.py` is most of what a verification flow needs.
- **Breached-password checking.** The blocklist in `common_passwords.py` covers
  the obvious cases. Have `password_problems()` also query the
  [Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API,
  which uses k-anonymity — you send the first five characters of the SHA-1 hash,
  never the password.
- **Test a real tag on a real phone.** Everything here is verified in the test
  suite and a desktop browser, but the loop that actually matters — phone taps
  tag, browser opens, information appears — needs a physical NTAG and two
  handsets. Do that before anyone wears one.

## This is not a medical service

Auraline stores what a person chooses to write down and shows it back to them.
It is not monitored, it gives no medical advice, and it cannot summon help.
Those limits are stated plainly on the site itself.
# seizure
