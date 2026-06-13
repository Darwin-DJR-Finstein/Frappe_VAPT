"""Restrict app-version disclosure to Administrator.

Three leak paths are closed:

1. The whitelisted API ``frappe.utils.change_log.get_versions`` — overridden via
   ``override_whitelisted_methods`` in hooks.py.
2. The sibling ``update_last_known_versions``, which persists ``get_versions()``
   output onto the calling user's ``last_known_versions`` field — same override.
3. ``bootinfo.versions`` at ``apps/frappe/frappe/boot.py:100`` — that file does a
   direct ``from frappe.utils.change_log import get_versions``, so the override
   does not reach it. We monkey-patch ``frappe.boot.get_versions`` at module
   import time so the next call inside ``get_bootinfo`` resolves to our wrapper.

A defence-in-depth ``after_request`` scrubber strips known sensitive keys from
any JSON response on ``/api/method/frappe.utils.change_log.*`` for non-admins,
catching future leaks the framework might add.

Per-site overrides via ``site_config.json``:
    frappe_vapt_version_endpoint_disabled: 1
        Raise PermissionError for everyone except Administrator.
    frappe_vapt_version_endpoint_allowed_roles: ["System Manager", ...]
        Roles that should see full version data alongside Administrator.
    frappe_vapt_version_endpoint_hide_app_names: 1
        Replace app names with the literal key ``app`` so even custom-app names
        are not enumerable.
"""

from __future__ import annotations

import json

import frappe
import frappe.boot
from frappe import _
from frappe.utils.change_log import get_versions as _frappe_get_versions


SENSITIVE_KEYS: frozenset[str] = frozenset(
    {"version", "branch", "branch_version", "commit", "commit_hash", "build_version"}
)


# ---------------------------------------------------------------------------
# Whitelisted overrides
# ---------------------------------------------------------------------------

@frappe.whitelist()
def get_versions_safe() -> dict:
    if _is_disabled() and not _is_administrator():
        raise frappe.PermissionError(_("Version information is restricted."))
    versions = _frappe_get_versions()
    if _is_privileged():
        return versions
    return _redact_versions_dict(versions)


@frappe.whitelist()
def update_last_known_versions_safe() -> None:
    if _is_disabled() and not _is_administrator():
        raise frappe.PermissionError(_("Version information is restricted."))
    versions = _frappe_get_versions()
    if not _is_privileged():
        versions = _redact_versions_dict(versions)
    frappe.db.set_value(
        "User",
        frappe.session.user,
        "last_known_versions",
        json.dumps(versions),
        update_modified=False,
    )


# ---------------------------------------------------------------------------
# boot_session — registered in hooks.py
# ---------------------------------------------------------------------------

def redact_boot_versions(bootinfo) -> None:
    """Wipe bootinfo.versions for non-admins.

    The monkey-patch below covers the common ``bootinfo.versions = {...}``
    assignment at boot.py:100, but this hook also catches anything an upstream
    app may have written to ``bootinfo.versions`` in an earlier boot_session
    pass. Safe to run alongside the monkey-patch.
    """
    try:
        if _is_privileged():
            return
        if getattr(bootinfo, "versions", None):
            bootinfo.versions = {}
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: redact_boot_versions failed")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# after_request — registered in hooks.py
# ---------------------------------------------------------------------------

def scrub_version_response(response=None, request=None) -> None:
    """Strip sensitive keys from any JSON response on the change_log namespace."""
    try:
        if response is None or request is None:
            return

        path = getattr(request, "path", "") or ""
        if not path.startswith("/api/method/frappe.utils.change_log."):
            return

        if _is_privileged():
            return

        content_type = response.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            return

        body = response.get_data(as_text=True)
        if not body:
            return

        try:
            payload = json.loads(body)
        except ValueError:
            return

        _scrub_keys_recursive(payload)
        response.set_data(json.dumps(payload))
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: scrub_version_response failed")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_administrator() -> bool:
    return frappe.session.user == "Administrator"


def _is_privileged() -> bool:
    if _is_administrator():
        return True
    extra_roles = (frappe.conf or {}).get("frappe_vapt_version_endpoint_allowed_roles") or []
    if not extra_roles:
        return False
    try:
        user_roles = set(frappe.get_roles(frappe.session.user))
    except Exception:
        return False
    return bool(user_roles.intersection(extra_roles))


def _is_disabled() -> bool:
    return bool((frappe.conf or {}).get("frappe_vapt_version_endpoint_disabled"))


def _redact_versions_dict(versions: dict) -> dict:
    hide_names = bool((frappe.conf or {}).get("frappe_vapt_version_endpoint_hide_app_names"))
    out: dict = {}
    for app, info in versions.items():
        info = info if isinstance(info, dict) else {}
        key = "app" if hide_names else app
        out[key] = {
            "title": info.get("title") or app.title(),
            "description": info.get("description") or "",
        }
    return out


def _scrub_keys_recursive(obj) -> None:
    if isinstance(obj, dict):
        for sensitive in list(obj.keys()):
            if sensitive in SENSITIVE_KEYS:
                obj.pop(sensitive, None)
        for value in obj.values():
            _scrub_keys_recursive(value)
    elif isinstance(obj, list):
        for item in obj:
            _scrub_keys_recursive(item)


# ---------------------------------------------------------------------------
# Module-import-time monkey-patch
# ---------------------------------------------------------------------------
# boot.py:33 does `from frappe.utils.change_log import get_versions`, binding
# the original function into its own namespace. The override_whitelisted_methods
# hook does not affect this internal call. We replace the name in boot.py's
# namespace with a redacting wrapper so bootinfo.versions (assigned at
# boot.py:100) sees the role-aware function. This runs once per worker, the
# first time Frappe imports this module (lazily via override resolution or via
# the boot_session hook).

def _boot_get_versions_wrapper() -> dict:
    versions = _frappe_get_versions()
    if _is_privileged():
        return versions
    return {}


frappe.boot.get_versions = _boot_get_versions_wrapper
