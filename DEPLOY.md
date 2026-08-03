# Deploying Auraline to Render

Exact values for this project, in order. About twenty minutes, most of it
waiting for the first build.

**Region is already set to `singapore`** for both the database and the web
service. Nothing to choose — skip straight to step 1.

---

## Before you start

- A [Render](https://render.com) account — free, no card needed for the free tier
- A GitHub account
- `PRODUCTION_KEYS.txt` in the project root — your two secrets, already generated

---

## 1. Push to GitHub

```bash
git init
```

```bash
git add -A
```

```bash
git commit -m "Auraline: epilepsy awareness site"
```

Create an empty repository on GitHub, then:

```bash
git remote add origin https://github.com/YOUR-USERNAME/auraline.git
```

```bash
git branch -M main
```

```bash
git push -u origin main
```

### Check you are not committing secrets

```bash
git status --porcelain --ignored | findstr /C:".env" /C:"PRODUCTION_KEYS"
```

Both files should appear with `!!` in front, meaning ignored. If either shows
`A` (added), stop and remove it before pushing:

```bash
git rm --cached .env PRODUCTION_KEYS.txt
```

---

## 2. Create the Blueprint

1. In Render, click **New +** → **Blueprint**
2. Connect GitHub if prompted, and pick the repository
3. Render reads `render.yaml` and shows what it will create:

   | Resource | Name | Details |
   |---|---|---|
   | PostgreSQL | `auraline-db` | database `auraline`, user `auraline`, free plan, **Singapore** |
   | Web service | `auraline` | Python, free plan, **Singapore** |

4. It will prompt for the values marked `sync: false`. Fill them in here, or in
   step 3 — either works.
5. Click **Apply**

First build takes 3–5 minutes. It will likely fail its health check until step 3
is done: the app deliberately refuses to boot in production without its keys,
rather than running half-secure.

---

## 3. Set the environment variables

**auraline** service → **Environment** tab.

### Already handled — do not touch

| Variable | Value | Set by |
|---|---|---|
| `PYTHON_VERSION` | `3.12.7` | render.yaml |
| `FLASK_ENV` | `production` | render.yaml |
| `SECRET_KEY` | *auto-generated* | Render |
| `DATABASE_URL` | *wired to `auraline-db`* | Render |

### Add these yourself

The first two are in `PRODUCTION_KEYS.txt` — open it and copy each value.

| Variable | Value |
|---|---|
| `FIELD_ENCRYPTION_KEYS` | The Fernet key from `PRODUCTION_KEYS.txt` |
| `BLIND_INDEX_KEY` | The token from `PRODUCTION_KEYS.txt` |
| `ADMIN_USERNAMES` | The **username** you will register your own account with |

### Email

Without these, nobody can reset a forgotten password, and tag requests are
stored but never reach your inbox.

| Variable | Example |
|---|---|
| `CONTACT_EMAIL` | `you@gmail.com` |
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `587` |
| `SMTP_USERNAME` | `you@gmail.com` |
| `SMTP_PASSWORD` | A Gmail **App Password** — see below |
| `SMTP_FROM` | `you@gmail.com` |

> **Gmail App Password.** Your ordinary Google password will not work here and
> should never be pasted into a third-party service. Turn on 2-Step
> Verification, then go to
> [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords),
> create one for "Mail", and use that 16-character value.

Click **Save Changes**. Render redeploys automatically.

**Then delete `PRODUCTION_KEYS.txt`** from your computer. It is git-ignored, but
it should not sit on disk once the values are safely in Render — keep your only
other copy in a password manager.

---

## 4. Confirm it started

Service → **Logs**. A healthy start looks like this:

```
==> Running 'gunicorn wsgi:app --workers 2 --threads 2 --timeout 60'
[INFO] Starting gunicorn 23.0.0
[INFO] Listening at: http://0.0.0.0:10000
[INFO] Booting worker with pid: ...
==> Your service is live 🎉
```

Your URL is at the top of the service page — `https://auraline.onrender.com`, or
with a suffix if that name was taken.

Tables are created automatically on first boot. There is no migration step.

---

## 5. Register your own account

Go to `/create-account` and sign up **with the username you put in
`ADMIN_USERNAMES`**. That unlocks `/admin/tag-requests`, where tag requests
arrive. Anyone else visiting that URL gets a 404, so its existence is not
advertised.

Admin is an **account** check, not a device one: sign in with that account from
a laptop, a phone, anywhere, and the admin pages are there. Nothing in this
project is tied to a particular machine, browser or network.

If those pages 404 when you expect them not to, check the service logs. The
refusal writes a line saying whether anything is configured at all, and points
you at comparing the username on `/account` against `ADMIN_USERNAMES`.

---

## 6. Test the emergency tag properly

1. Sign in and fill in some of your record at `/my-details`
2. Go to `/my-information/emergency` and create your link
3. Open that link **on a different device that is not signed in** — a phone on
   mobile data is the honest test, because it proves the link works on its own
   rather than because your browser has a session
4. Confirm your information appears

Only write it to a physical NFC tag once that passes.

---

## 7. Fulfilling a physical tag request

When someone uses **Request a tag** while signed in, their request appears at
`/admin/tag-requests` with a **Reveal link** button. Clicking it shows their
emergency URL right there, so you can write it to an NTAG and post it.

If you need a link with no request open — replacing a lost tag in person, say
— use `/admin/emergency-links`, which lists every account and lets you search
by exact username or email.

Both are the one place in the app where you, not just the tag's owner, can see
that link — everywhere else it is invisible to everyone but them, including the
medical fields behind it. Neither page lists tokens in bulk: you reveal one at
a time, on a click, and every reveal is written into *that person's own*
access log as "Opened by the site host" at `/my-information/emergency` — so
they always know it happened, the same way they would see an ordinary scan.
This is stated on the site's privacy page, not hidden: someone who does not
want you to have this ability can set up their own tag and print their own QR
code instead of requesting a physical one.

---

## Troubleshooting

**`Refusing to start in production without: ...`**
A key is missing or misspelled in the Environment tab. The message names which
one. This is the app protecting you, not a bug.

**Build fails on `PYTHON_VERSION`**
Render no longer offers that exact patch release. Change the value to `3.12` or
`3.13` in `render.yaml` and push.

**`could not translate host name`, or the database will not connect**
The database and web service are in different regions. Both must say
`singapore`. Check `render.yaml` and the Render dashboard agree.

**Health check fails, but the logs show gunicorn listening**
Check the port in `Listening at:` is Render's `$PORT` (usually 10000), not 8000.
It should be automatic — gunicorn reads `PORT` from the environment.

**Works, then returns 502 after a while**
Free instances sleep after 15 minutes idle. The next request takes 30–60 seconds
to wake them. This is the free tier behaving as designed.

---

## Two things that will bite you later

**Free Postgres is deleted after 30 days.** Render emails a warning first. On an
ordinary hobby project that is an annoyance; here it means people lose medical
information they are relying on. Upgrade the database (currently about $7/month)
before you tell anyone to use this, or be clear with yourself that it is a demo.

**The free web service sleeps.** A cold scan of an NFC tag can take 30–60 seconds
to load. For an emergency card that is a real limitation, not just a nuisance.
The paid instance tier removes it.

**Back up `FIELD_ENCRYPTION_KEYS` outside Render.** If the service is ever
deleted and that key goes with it, every stored record is permanently
unreadable. There is no recovery path. That is the point of the design, but it
cuts both ways.

---

## Changing region later

You cannot move a Render database between regions — you would create a new one
and migrate the data. If you need to change before launch, while the database is
still empty, it is painless:

1. Edit `render.yaml` and set **both** `region:` values (database and web
   service) to the same new value
2. Delete the `auraline-db` database in Render
3. Push, and re-apply the Blueprint

| Value | Location |
|---|---|
| `singapore` | Asia — **current** |
| `frankfurt` | Europe |
| `oregon` | US West |
| `ohio` | US East |
| `virginia` | US East |

They must always match. The database and web service talk over Render's internal
network, which does not cross regions.

---

## Custom domain (optional)

Service → **Settings** → **Custom Domains** → add your domain, then create the
CNAME record Render shows you at your registrar. Render provisions the TLS
certificate automatically.

No code change is needed. The app builds its own URLs from the incoming request,
so emailed password-reset links and emergency tag links pick up the new domain
by themselves — though any NFC tag already written still points at the old
address, so write tags after the domain is settled.
