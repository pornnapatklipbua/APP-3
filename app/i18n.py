"""Language switching between the English and Thai pages.

Deliberately templates rather than gettext catalogues. The site has two
languages and a lot of long-form prose, and whoever translates it should be
able to edit HTML directly without extracting strings, compiling `.mo` files,
or installing a toolchain. Each Thai page is a plain template under
``templates/th/`` mirroring the English path.

The mechanism, in three pieces:

* :func:`bilingual` registers one view function at two URLs -- ``/account``
  and ``/th/account`` -- as endpoints ``account`` and ``th_account``. The
  request handling is never duplicated, only the wording.
* :func:`render_localised` picks the template from the URL that was matched,
  falling back to the English one if the Thai file does not exist yet. A
  missing translation degrades to English rather than a 500.
* :func:`url_for_language` maps the current endpoint to its counterpart, so
  the dropdown lands on the same page in the other language.

Adding a translated page is therefore: swap ``@bp.route`` for ``@bilingual``,
call ``render_localised``, and drop a template into ``templates/th/``.
"""

from __future__ import annotations

from flask import render_template, request, url_for
from werkzeug.routing import BuildError

# (code, label shown in the dropdown, flag partial)
#
# The Thai label is written in English on purpose -- nothing in this project
# writes Thai text. Replace it with the endonym when translating.
LANGUAGES: tuple[tuple[str, str, str], ...] = (
    ("en", "English", "partials/flag-en.svg"),
    ("th", "Thai", "partials/flag-th.svg"),
)

DEFAULT_LANGUAGE = "en"
THAI_PREFIX = "/th"
_ENDPOINT_PREFIX = "th_"

HOME_ENDPOINT: dict[str, str] = {"en": "main.index", "th": "main.th_index"}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def bilingual(blueprint, rule: str, **options):
    """Register a view at both ``rule`` and ``/th`` + ``rule``.

    One view function, two URLs, two endpoint names. Anything the view does --
    queries, validation, redirects -- happens once; only the template differs.
    """

    def decorator(view):
        endpoint = options.pop("endpoint", view.__name__)
        blueprint.add_url_rule(rule, endpoint, view, **options)
        blueprint.add_url_rule(
            THAI_PREFIX + rule, _ENDPOINT_PREFIX + endpoint, view, **options
        )
        return view

    return decorator


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def current_language() -> str:
    """Read the language off the URL rather than a cookie or session.

    A language a visitor cannot see in the address bar is one they cannot
    bookmark, share, or get back to after signing in.
    """
    path = request.path
    if path == THAI_PREFIX or path.startswith(THAI_PREFIX + "/"):
        return "th"
    return DEFAULT_LANGUAGE


def render_localised(template_name: str, **context):
    """Render the Thai template when on a Thai URL, else the English one.

    Passing a list to ``render_template`` uses the first template that exists,
    so a page whose Thai file has not been written yet quietly serves English
    instead of erroring.
    """
    if current_language() == "th":
        return render_template([f"th/{template_name}", template_name], **context)
    return render_template(template_name, **context)


# ---------------------------------------------------------------------------
# Switching
# ---------------------------------------------------------------------------


def counterpart_endpoint(endpoint: str, code: str) -> str:
    """``records.edit`` <-> ``records.th_edit``."""
    blueprint, _, name = endpoint.rpartition(".")
    base = name[len(_ENDPOINT_PREFIX):] if name.startswith(_ENDPOINT_PREFIX) else name
    target = _ENDPOINT_PREFIX + base if code == "th" else base
    return f"{blueprint}.{target}" if blueprint else target


def lurl_for(endpoint: str, **values) -> str:
    """``url_for`` that keeps the visitor in the language they are already in.

    Registered as the template global ``url_for``, which is what lets the Thai
    templates be verbatim copies of the English ones with only the wording
    changed: ``url_for('records.edit')`` resolves to ``records.th_edit`` on a
    Thai page and ``records.edit`` on an English one.

    Endpoints with no counterpart -- ``static``, the admin pages, the public
    emergency card -- raise BuildError and fall through to the original, so
    this is safe to apply blanket-wide.
    """
    try:
        return url_for(counterpart_endpoint(endpoint, current_language()), **values)
    except BuildError:
        return url_for(endpoint, **values)


def url_for_language(code: str) -> str:
    """Where the dropdown should send someone switching to ``code``.

    Keeps the current page where a counterpart exists, carrying URL arguments
    across so a password-reset link or similar survives the switch. Falls back
    to that language's home page otherwise -- a dropdown that silently does
    nothing is worse than one that moves you somewhere real.
    """
    if code == current_language():
        return request.full_path if request.query_string else request.path

    endpoint = request.endpoint
    if endpoint:
        try:
            return url_for(
                counterpart_endpoint(endpoint, code), **(request.view_args or {})
            )
        except BuildError:
            pass
    return url_for(HOME_ENDPOINT[code])


def has_translation() -> bool:
    """Whether the page being rendered exists in both languages."""
    endpoint = request.endpoint
    if not endpoint:
        return False
    other = "th" if current_language() == "en" else "en"
    try:
        url_for(counterpart_endpoint(endpoint, other), **(request.view_args or {}))
        return True
    except BuildError:
        return False


def language_context() -> dict:
    """Injected into every template by the application factory."""
    return {
        "current_language": current_language(),
        "languages": LANGUAGES,
        "url_for_language": url_for_language,
        "page_has_translation": has_translation(),
    }
