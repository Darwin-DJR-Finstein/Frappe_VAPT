"""Strip HTML/markup from user-submitted comment content.

Defends against stored XSS in the Comment doctype by ensuring that, regardless
of what `frappe.desk.form.utils.add_comment` or any other entry point receives,
the persisted `doc.content` for user-typed comments is plain text wrapped in
the standard Quill read-mode envelope. System-generated comments (workflow
transitions, field-change logs, likes, assignments, etc.) are left alone.

Per-site overrides via site_config.json:
    frappe_vapt_disable_comment_sanitization: 1
    frappe_vapt_comment_allowed_tags: ["b", "i", "em", "strong", "br", "p"]
"""

from __future__ import annotations

import re
from html import unescape as html_unescape

import bleach
import frappe


DEFAULT_ALLOWED_TAGS: tuple[str, ...] = ()
DEFAULT_ALLOWED_ATTRIBUTES: dict[str, list[str]] = {"a": ["href", "title"]}
ALLOWED_URL_SCHEMES: tuple[str, ...] = ("http", "https", "mailto")

# Tags whose entire body (not just the open/close markers) must be discarded.
# bleach with strip=True only removes the tag markers; without this pre-pass
# the inner text of e.g. <script>alert(1)</script> would survive as "alert(1)".
_BODY_DROP_TAGS = ("script", "style", "noscript", "iframe", "object", "embed", "applet")
_BODY_DROP_RE = re.compile(
    r"<\s*(" + "|".join(_BODY_DROP_TAGS) + r")\b[^>]*>.*?<\s*/\s*\1\s*>",
    re.IGNORECASE | re.DOTALL,
)

# Convert paragraph / line-break boundaries to \n before tag stripping so that
# a multi-paragraph plain-text comment retains its line structure.
_BREAK_RE = re.compile(r"<\s*br\s*/?\s*>|</\s*(?:p|div|li)\s*>", re.IGNORECASE)

QUILL_WRAPPER = '<div class="ql-editor read-mode">{body}</div>'


def sanitize_comment_content(doc, method=None) -> None:
    """Comment `validate` hook — rewrite doc.content as safe plain text."""
    try:
        if _bypass_active():
            return
        if getattr(doc, "comment_type", None) != "Comment":
            return

        raw = (getattr(doc, "content", None) or "").strip()
        if not raw:
            return

        tags = _allowed_tags()

        # Pass 0 — single HTML-entity unescape.
        decoded = html_unescape(raw)

        # Strip the whole bodies of dangerous container tags before bleach,
        # so the text content of <script> etc. doesn't leak through.
        without_bodies = _BODY_DROP_RE.sub("", decoded)

        # Preserve line structure across paragraph / break boundaries.
        with_newlines = _BREAK_RE.sub("\n", without_bodies)

        # Pass 1 — bleach with the configured allowlist and scheme filter.
        cleaned = bleach.clean(
            with_newlines,
            tags=list(tags),
            attributes=DEFAULT_ALLOWED_ATTRIBUTES if tags else {},
            protocols=list(ALLOWED_URL_SCHEMES),
            strip=True,
            strip_comments=True,
        )

        if not tags:
            # Strict mode: bleach already escaped any stray <, >, &. Turn the
            # preserved newlines into <br> for the activity feed. Bleach
            # output is safe HTML, so inserting <br> between chunks is safe.
            text = cleaned.strip()
            body = f"<p>{text.replace(chr(10), '<br>')}</p>" if text else "<p></p>"
        else:
            body = cleaned.strip() or "<p></p>"

        doc.content = QUILL_WRAPPER.format(body=body)
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: sanitize_comment_content failed")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bypass_active() -> bool:
    flags = frappe.flags
    for flag in ("in_install", "in_migrate", "in_patch", "in_setup_wizard", "in_test"):
        if getattr(flags, flag, False):
            return True

    conf = frappe.conf or {}
    return bool(conf.get("frappe_vapt_disable_comment_sanitization"))


def _allowed_tags() -> tuple[str, ...]:
    override = (frappe.conf or {}).get("frappe_vapt_comment_allowed_tags")
    if not override:
        return DEFAULT_ALLOWED_TAGS
    return tuple(t.lower() for t in override)
