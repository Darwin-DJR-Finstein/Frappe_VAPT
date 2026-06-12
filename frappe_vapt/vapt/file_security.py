"""Upload content inspection + serve-time header hardening.

Layer 1 — reject_dangerous_files: a File doctype `validate` hook that reads the
uploaded bytes before they are persisted and rejects anything containing
executable or markup content (script tags, SVG, HTML, XML, PE/shebang headers,
etc.). For declared images it additionally verifies the magic bytes match a
known image format, defeating rename-the-extension bypasses.

Layer 2 — harden_file_response: an `after_request` hook that forces
Content-Disposition: attachment, a sandboxing CSP, and nosniff on any response
serving a file with a dangerous extension. Closes the hole for files uploaded
before this app was installed.

Per-site overrides via site_config.json:
    frappe_vapt_disable_content_inspection: 1
    frappe_vapt_allow_dangerous_upload_roles: ["System Manager", ...]
    frappe_vapt_dangerous_extensions: [".svg", ...]   # override default set
"""

from __future__ import annotations

import os
from urllib.parse import quote

import frappe
from frappe import _


DANGEROUS_MAGIC: tuple[bytes, ...] = (
    b"<svg",
    b"<script",
    b"<!doctype html",
    b"<html",
    b"<?xml",
    b"<iframe",
    b"<object",
    b"<embed",
    b"<applet",
    b"javascript:",
    b"data:text/html",
    b"data:image/svg+xml",
    b"<?php",
    b"<%",
)

EXECUTABLE_PREFIXES: tuple[bytes, ...] = (
    b"MZ\x90\x00",
    b"#!/",
    b"#! ",
)

IMAGE_MAGIC: dict[str, tuple[bytes, ...]] = {
    "png": (b"\x89PNG\r\n\x1a\n",),
    "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF87a", b"GIF89a"),
    "webp": (b"RIFF",),
    "bmp": (b"BM",),
    "ico": (b"\x00\x00\x01\x00",),
    "tiff": (b"II*\x00", b"MM\x00*"),
}

IMAGE_EXT_TO_KEY: dict[str, str] = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".webp": "webp",
    ".bmp": "bmp",
    ".ico": "ico",
    ".tiff": "tiff",
}

DEFAULT_DANGEROUS_EXTS: frozenset[str] = frozenset(
    {".svg", ".svgz", ".html", ".htm", ".xhtml", ".xml", ".mhtml"}
)

SCAN_BYTES: int = 16 * 1024


# ---------------------------------------------------------------------------
# Layer 1 — upload content inspection
# ---------------------------------------------------------------------------

def reject_dangerous_files(doc, method=None):
    if _bypass_active():
        return

    buf = _get_upload_bytes(doc)
    if not buf:
        return

    ext = _file_extension(doc)

    # Pass A — markup / script / executable signature scan.
    hit = _scan_for_dangerous_markup(buf)
    if hit:
        frappe.throw(
            _(
                "This file contains executable or markup content "
                "(detected marker: {0}) and cannot be uploaded."
            ).format(hit),
            frappe.ValidationError,
        )

    # Pass B — image magic verification when the upload claims to be an image.
    if _claims_to_be_image(doc, ext) and not _matches_image_magic(buf, ext):
        frappe.throw(
            _(
                "Uploaded file is declared as an image but its content is not "
                "a recognised image format."
            ),
            frappe.ValidationError,
        )


def _get_upload_bytes(doc) -> bytes:
    raw = getattr(doc, "_content", None)
    if raw is None:
        try:
            raw = doc.get_content()
        except Exception:
            raw = None
    if raw is None:
        return b""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return bytes(raw[:SCAN_BYTES])


def _scan_for_dangerous_markup(buf: bytes) -> str | None:
    for prefix in EXECUTABLE_PREFIXES:
        if buf.startswith(prefix):
            return prefix.decode("latin-1", "replace")

    lowered = buf.lower()
    for needle in DANGEROUS_MAGIC:
        if needle in lowered:
            return needle.decode("latin-1", "replace")

    return None


def _claims_to_be_image(doc, ext: str) -> bool:
    if ext in IMAGE_EXT_TO_KEY:
        return True

    parent_doctype = getattr(doc, "attached_to_doctype", None)
    parent_field = getattr(doc, "attached_to_field", None)
    if not parent_doctype or not parent_field:
        return False

    try:
        meta = frappe.get_meta(parent_doctype)
        field = meta.get_field(parent_field)
    except Exception:
        return False

    return bool(field) and field.fieldtype == "Attach Image"


def _matches_image_magic(buf: bytes, ext: str) -> bool:
    key = IMAGE_EXT_TO_KEY.get(ext)
    if key is None:
        # Unknown image extension but the field is Attach Image — accept any
        # of the known image magics.
        candidates = [m for sigs in IMAGE_MAGIC.values() for m in sigs]
    else:
        candidates = list(IMAGE_MAGIC[key])

    for sig in candidates:
        if buf.startswith(sig):
            if sig == b"RIFF":
                # WebP: bytes 8..12 must spell WEBP.
                return buf[8:12] == b"WEBP"
            return True
    return False


def _file_extension(doc) -> str:
    name = getattr(doc, "file_name", None) or getattr(doc, "file_url", None) or ""
    return os.path.splitext(name)[1].lower()


def _bypass_active() -> bool:
    flags = frappe.flags
    for flag in ("in_install", "in_migrate", "in_patch", "in_setup_wizard", "in_test"):
        if getattr(flags, flag, False):
            return True

    conf = frappe.conf or {}
    if conf.get("frappe_vapt_disable_content_inspection"):
        return True

    allowed_roles = conf.get("frappe_vapt_allow_dangerous_upload_roles") or []
    if allowed_roles:
        try:
            user_roles = set(frappe.get_roles(frappe.session.user))
        except Exception:
            user_roles = set()
        if user_roles.intersection(allowed_roles):
            return True

    return False


# ---------------------------------------------------------------------------
# Layer 2 — serve-time header hardening
# ---------------------------------------------------------------------------

def harden_file_response(response=None, request=None):
    try:
        if response is None or request is None:
            return

        path = getattr(request, "path", "") or ""
        if not (path.startswith("/private/files/") or path.startswith("/files/")):
            return

        ext = os.path.splitext(path)[1].lower()
        dangerous = _dangerous_extensions()
        if ext not in dangerous:
            return

        headers = response.headers
        existing_disposition = headers.get("Content-Disposition", "")
        if "attachment" not in existing_disposition.lower():
            basename = os.path.basename(path) or "download"
            quoted = quote(basename, safe="")
            headers["Content-Disposition"] = (
                f'attachment; filename="{basename}"; '
                f"filename*=UTF-8''{quoted}"
            )

        headers["Content-Security-Policy"] = (
            "sandbox; default-src 'none'; style-src 'unsafe-inline'"
        )
        headers["X-Content-Type-Options"] = "nosniff"
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: harden_file_response failed")
        except Exception:
            pass


def _dangerous_extensions() -> frozenset[str]:
    override = (frappe.conf or {}).get("frappe_vapt_dangerous_extensions")
    if override:
        return frozenset(e.lower() for e in override)
    return DEFAULT_DANGEROUS_EXTS
