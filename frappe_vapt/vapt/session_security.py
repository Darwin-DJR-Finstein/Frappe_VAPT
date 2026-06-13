"""Session hijacking hardening for Frappe.

Three controls compose to neutralise stolen / replayed session cookies:

1. ``enforce_session_limit`` (``on_session_creation``) — calls
   ``frappe.sessions.clear_sessions(... force=False)`` so Frappe's per-user
   ``User.simultaneous_sessions`` field is honoured. A new login keeps the
   user's N newest sessions and drops the rest. Default ``simultaneous_sessions``
   is 1 (Frappe ships this), so out of the box a new login kills the previous
   one; sites raise the per-user value to allow multi-device. Optional
   site-wide cap ``frappe_vapt_session_max_per_user`` overrides every User doc.

2. ``record_session_fingerprint`` (``on_session_creation``) +
   ``enforce_session_fingerprint`` (``auth_hooks``) — record the client's
   IP-prefix and User-Agent SHA-256 at login, compare on every request, and
   terminate the session on mismatch. Defeats a stolen sid replayed from a
   different network or browser.

3. ``harden_session_cookie`` (``after_request``) — rewrite the ``sid`` cookie's
   ``SameSite`` attribute from ``Lax`` to ``Strict`` so cross-site link clicks
   don't carry it.

Administrator is treated the same as every other user — no exemption. If you
need an emergency back door (Administrator locked out by misconfiguration), use
`frappe_vapt_disable_session_binding: 1` in site_config.json from the server CLI
(`bench --site <site> set-config frappe_vapt_disable_session_binding 1`) and
restart workers. Guest is still skipped because it is the anonymous bucket that
public visitors share — binding it would cause every visitor to evict every
other.

Per-site overrides via ``site_config.json``:

    frappe_vapt_disable_session_clear: 1
        Skip Hook 1 entirely.
    frappe_vapt_session_max_per_user: <int>
        Site-wide cap on simultaneous sessions; overrides per-user field.
    frappe_vapt_disable_session_binding: 1
        Skip Hook 2 entirely.
    frappe_vapt_session_ipv4_prefix: 0..32         (default 24)
        Prefix bits for IPv4 binding. 0 disables IPv4 binding.
    frappe_vapt_session_ipv6_prefix: 0..128        (default 64)
        Prefix bits for IPv6 binding. 0 disables IPv6 binding.
    frappe_vapt_session_log_full_ip: 1
        Log full IP addresses in termination warnings (default: prefixes only).
    frappe_vapt_session_samesite: "Strict" | "Lax"  (default "Strict")
        Override SameSite attribute on the rewritten sid cookie.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

import frappe


DEFAULT_IPV4_PREFIX: int = 24
DEFAULT_IPV6_PREFIX: int = 64
DEFAULT_SAMESITE: str = "Strict"

_SID_COOKIE_RE = re.compile(r"^\s*sid\s*=", re.IGNORECASE)
_SAMESITE_RE = re.compile(r";\s*SameSite\s*=\s*[^;]+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Hook 1 — enforce per-user session limit
# ---------------------------------------------------------------------------

def enforce_session_limit(login_manager=None) -> None:
    try:
        user = getattr(frappe.session, "user", None)
        if not user or user == "Guest":
            return  # Guest is the anonymous bucket — never enforce limits there.
        if (frappe.conf or {}).get("frappe_vapt_disable_session_clear"):
            return

        # Optional site-wide cap. Temporarily override the per-user field in
        # memory so frappe.sessions.get_sessions_to_clear reads our cap value.
        site_cap = (frappe.conf or {}).get("frappe_vapt_session_max_per_user")
        cap_override = None
        if site_cap is not None:
            try:
                cap_override = max(1, int(site_cap))
            except (TypeError, ValueError):
                cap_override = None

        if cap_override is not None:
            try:
                frappe.db.set_value(
                    "User",
                    user,
                    "simultaneous_sessions",
                    cap_override,
                    update_modified=False,
                )
            except Exception:
                # If we can't write the override, the per-user field still
                # applies — fail-open into Frappe's native limit, not into
                # unlimited sessions.
                pass

        from frappe.sessions import clear_sessions

        clear_sessions(user, keep_current=True, force=False)
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: enforce_session_limit failed")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Hook 2 — fingerprint binding
# ---------------------------------------------------------------------------

def record_session_fingerprint(login_manager=None) -> None:
    try:
        user = getattr(frappe.session, "user", None)
        if not user or user == "Guest":
            return
        data = getattr(frappe.session, "data", None)
        if not isinstance(data, dict):
            return
        data["vapt_session_binding"] = _compute_fingerprint()

        # The session row + cache were already written inside Session.start()
        # BEFORE this hook fired. Without an explicit flush, the binding lives
        # only in memory for the current request and is gone on the next one.
        # Force-update sessiondata + Redis cache so subsequent requests can
        # read it back from frappe.session.data.
        session_obj = getattr(frappe.local, "session_obj", None)
        if session_obj is not None and hasattr(session_obj, "update"):
            session_obj.update(force=True)
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: record_session_fingerprint failed")
        except Exception:
            pass


def enforce_session_fingerprint() -> None:
    if _is_binding_disabled():
        return
    session = getattr(frappe, "session", None)
    if not session:
        return
    user = getattr(session, "user", None)
    if not user or user == "Guest":
        return

    data = getattr(session, "data", None) or {}
    stored = data.get("vapt_session_binding") if isinstance(data, dict) else None
    if not stored:
        # Legacy session — predates this app. Don't terminate; it will rebind
        # on next login.
        return

    current = _compute_fingerprint()
    if _matches(stored, current):
        return

    _terminate_session(user=user, stored=stored, current=current)
    raise frappe.SessionStopped("Session terminated: client environment changed.")


# ---------------------------------------------------------------------------
# Hook 3 — cookie hardening
# ---------------------------------------------------------------------------

def harden_session_cookie(response=None, request=None) -> None:
    try:
        if response is None:
            return
        samesite = _samesite_value()
        if samesite is None:
            return

        cookies = response.headers.getlist("Set-Cookie")
        if not cookies:
            return

        rewritten = []
        changed = False
        for cookie in cookies:
            if not _SID_COOKIE_RE.match(cookie):
                rewritten.append(cookie)
                continue
            new_cookie = _rewrite_samesite(cookie, samesite)
            if new_cookie != cookie:
                changed = True
            rewritten.append(new_cookie)

        if not changed:
            return

        # Replace the Set-Cookie headers.
        del response.headers["Set-Cookie"]
        for cookie in rewritten:
            response.headers.add("Set-Cookie", cookie)
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: harden_session_cookie failed")
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_fingerprint() -> dict:
    ip = ""
    ua = ""
    try:
        ip = getattr(frappe.local, "request_ip", None) or ""
        request = getattr(frappe.local, "request", None)
        if request is not None:
            ua = request.headers.get("User-Agent", "") or ""
    except Exception:
        pass

    return {
        "ip_prefix": _ip_prefix(ip),
        "ua_sha": hashlib.sha256(ua.encode("utf-8", "replace")).hexdigest() if ua else "",
    }


def _matches(stored: dict, current: dict) -> bool:
    if not isinstance(stored, dict) or not isinstance(current, dict):
        return False

    stored_ip = stored.get("ip_prefix") or ""
    current_ip = current.get("ip_prefix") or ""
    # Only enforce IP if both sides have one. An empty prefix on either side
    # (e.g. binding disabled by knob, or no IP captured) means "don't compare".
    if stored_ip and current_ip and stored_ip != current_ip:
        return False

    stored_ua = stored.get("ua_sha") or ""
    current_ua = current.get("ua_sha") or ""
    if stored_ua and current_ua and stored_ua != current_ua:
        return False

    return True


def _ip_prefix(ip: str) -> str:
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""

    if isinstance(addr, ipaddress.IPv4Address):
        bits = _conf_int("frappe_vapt_session_ipv4_prefix", DEFAULT_IPV4_PREFIX)
        if bits <= 0:
            return ""
        bits = min(bits, 32)
        net = ipaddress.ip_network(f"{ip}/{bits}", strict=False)
        return str(net.network_address)

    bits = _conf_int("frappe_vapt_session_ipv6_prefix", DEFAULT_IPV6_PREFIX)
    if bits <= 0:
        return ""
    bits = min(bits, 128)
    net = ipaddress.ip_network(f"{ip}/{bits}", strict=False)
    return str(net.network_address)


def _terminate_session(user: str, stored: dict, current: dict) -> None:
    sid = getattr(frappe.session, "sid", None)
    log_full = bool((frappe.conf or {}).get("frappe_vapt_session_log_full_ip"))
    try:
        reason = (
            f"frappe_vapt session terminated for user={user}: "
            f"stored_ip={stored.get('ip_prefix') if log_full else '<redacted>'}, "
            f"current_ip={current.get('ip_prefix') if log_full else '<redacted>'}, "
            f"ua_match={stored.get('ua_sha') == current.get('ua_sha')}"
        )
        frappe.log_error(message=reason, title="frappe_vapt: session terminated")
    except Exception:
        pass

    try:
        if sid:
            from frappe.sessions import delete_session

            delete_session(sid, user=user, reason="frappe_vapt: fingerprint mismatch")
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: delete_session failed during termination")
        except Exception:
            pass

    try:
        login_manager = getattr(frappe.local, "login_manager", None)
        if login_manager is not None:
            login_manager.logout(user=user)
    except Exception:
        pass


def _rewrite_samesite(cookie: str, samesite: str) -> str:
    if _SAMESITE_RE.search(cookie):
        return _SAMESITE_RE.sub(f"; SameSite={samesite}", cookie)
    return cookie.rstrip("; ") + f"; SameSite={samesite}"


def _is_binding_disabled() -> bool:
    return bool((frappe.conf or {}).get("frappe_vapt_disable_session_binding"))


def _samesite_value():
    raw = (frappe.conf or {}).get("frappe_vapt_session_samesite", DEFAULT_SAMESITE)
    if raw is None or raw is False:
        return None
    raw = str(raw).strip().capitalize()
    if raw not in ("Strict", "Lax", "None"):
        return DEFAULT_SAMESITE
    return raw


def _conf_int(key: str, default: int) -> int:
    val = (frappe.conf or {}).get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default
