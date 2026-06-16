"""Strip stack traces / internal paths / runtime version from API error JSON.

Frappe leaks full Python tracebacks (including `apps/frappe/...` paths and the
exact Python version) in JSON API error responses when its built-in
``allow_error_traceback`` System Setting is on, and even with it off the
``exc_type`` field still discloses the exception class name. This module
neutralises both regardless of the System Setting.

The control runs as an ``after_request`` hook. On any 4xx/5xx JSON response for
a non-privileged caller, it walks the payload and:

* Removes ``exc``, ``exception``, ``_error_message``, ``_server_messages``,
  ``traceback``, ``stack``, ``stacktrace`` at any depth.
* Replaces ``exc_type`` with the generic literal ``"Error"`` (preserved key
  so client code that probes the field still gets a string).
* Adds a friendly ``message`` if the payload doesn't already have one.

Administrator and any role listed in
``site_config.frappe_vapt_error_scrub_allowed_roles`` see the original response
unchanged so they can still debug.

Per-site overrides via ``site_config.json``:

    frappe_vapt_disable_error_scrub: 1
        Emergency kill switch — pass error responses through unchanged.
    frappe_vapt_error_scrub_allowed_roles: ["System Manager", ...]
        Roles that see original errors alongside Administrator.
    frappe_vapt_error_scrub_keys: ["exc", "exception", "stack", ...]
        Override the default set of keys to strip.
"""

from __future__ import annotations

import json

import frappe


DEFAULT_SCRUB_KEYS: frozenset[str] = frozenset(
    {
        "exc",
        "exception",
        "_error_message",
        "_server_messages",
        "traceback",
        "stack",
        "stacktrace",
    }
)
GENERIC_EXC_TYPE: str = "Error"
GENERIC_MESSAGE: str = "An error occurred. Contact the administrator if it persists."


def scrub_error_response(response=None, request=None) -> None:
    """``after_request`` hook — strip leaky keys from error JSON for non-admins."""
    try:
        if response is None:
            return

        status = getattr(response, "status_code", 200)
        if status < 400:
            return

        if _is_disabled() or _is_privileged():
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

        scrub_keys = _scrub_keys()
        _scrub_payload(payload, scrub_keys)

        if isinstance(payload, dict):
            if "exc_type" in payload:
                payload["exc_type"] = GENERIC_EXC_TYPE
            if not payload.get("message"):
                payload["message"] = GENERIC_MESSAGE

        response.set_data(json.dumps(payload))
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: scrub_error_response failed")
        except Exception:
            pass


def _scrub_payload(obj, scrub_keys: frozenset[str]) -> None:
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if key in scrub_keys:
                obj.pop(key, None)
        for value in obj.values():
            _scrub_payload(value, scrub_keys)
    elif isinstance(obj, list):
        for item in obj:
            _scrub_payload(item, scrub_keys)


def _is_disabled() -> bool:
    return bool((frappe.conf or {}).get("frappe_vapt_disable_error_scrub"))


def _is_privileged() -> bool:
    user = getattr(frappe.session, "user", None)
    if user == "Administrator":
        return True
    extra_roles = (frappe.conf or {}).get("frappe_vapt_error_scrub_allowed_roles") or []
    if not extra_roles:
        return False
    try:
        user_roles = set(frappe.get_roles(user))
    except Exception:
        return False
    return bool(user_roles.intersection(extra_roles))


def _scrub_keys() -> frozenset[str]:
    override = (frappe.conf or {}).get("frappe_vapt_error_scrub_keys")
    if override:
        return frozenset(override)
    return DEFAULT_SCRUB_KEYS
