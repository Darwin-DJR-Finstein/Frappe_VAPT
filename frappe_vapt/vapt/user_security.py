"""Role-based gate on User-doctype read access.

Closes the user-enumeration leak in `frappe.client.get_list("User", ...)` and
related endpoints. The policy is driven entirely by Frappe's existing role /
permission model — there is no hardcoded user list.

Three hooks compose to enforce it:

* ``get_user_query_conditions`` — registered as ``permission_query_conditions["User"]``.
  Returns an SQL WHERE fragment that restricts non-privileged callers to their
  own row. AND-joined with Frappe's built-in STANDARD_USERS filter by
  ``apps/frappe/frappe/model/db_query.py:1138``.

* ``has_user_permission`` — registered as ``has_permission["User"]``. Gates the
  single-document read path (``frappe.client.get(doctype="User", name=...)``).

* ``user_query_safe`` — registered as ``standard_queries["User"]``. Wraps
  Frappe's autocomplete query function to (a) set a request-scoped flag so
  Hook 1 uses the ``select`` permtype instead of ``read``, (b) require a
  minimum search-text length, and (c) cap the page size.

Per-site overrides via ``site_config.json``:
    frappe_vapt_user_enumeration_disabled: 1
        Hard kill switch. Non-Administrator callers always get an empty result.
    frappe_vapt_user_autocomplete_min_chars: 0|1|2|3...
        Minimum search-text length before autocomplete returns matches.
        Default 3. Set to 0 for legacy UX.
    frappe_vapt_user_autocomplete_max_page_len: <int>
        Hard cap on autocomplete page size. Default 20.
"""

from __future__ import annotations

import frappe


DEFAULT_AUTOCOMPLETE_MIN_CHARS: int = 3
DEFAULT_AUTOCOMPLETE_MAX_PAGE_LEN: int = 20


# ---------------------------------------------------------------------------
# Hook 1 — permission_query_conditions
# ---------------------------------------------------------------------------

def get_user_query_conditions(user, doctype=None) -> str:
    """Restrict User list queries to self when caller lacks the required perm."""
    if user == "Administrator":
        return ""
    if _is_killed():
        return "1=0"
    ptype = _required_ptype()
    if _has_unrestricted_perm(user, ptype):
        return ""
    return f"`tabUser`.name = {frappe.db.escape(user)}"


# ---------------------------------------------------------------------------
# Hook 2 — has_permission
# ---------------------------------------------------------------------------

def has_user_permission(doc, ptype="read", user=None) -> bool:
    """Single-document read gate on User."""
    try:
        user = user or frappe.session.user
        if user == "Administrator":
            return True
        if _is_killed():
            return False

        doc_name = None
        if doc is not None:
            doc_name = getattr(doc, "name", None) or (doc if isinstance(doc, str) else None)
        if doc_name and doc_name == user:
            return True

        return _has_unrestricted_perm(user, "read")
    except Exception:
        try:
            frappe.log_error(title="frappe_vapt: has_user_permission failed")
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Hook 3 — standard_queries (autocomplete)
# ---------------------------------------------------------------------------

def user_query_safe(doctype, txt, searchfield, start, page_len, filters):
    """Flag-aware wrapper around Frappe's user_query."""
    from frappe.core.doctype.user.user import user_query as _original

    user = frappe.session.user
    if user == "Administrator":
        return _original(doctype, txt, searchfield, start, page_len, filters)

    if _is_killed():
        return []

    min_chars = _min_chars()
    txt_str = (txt or "").strip()
    if min_chars and len(txt_str) < min_chars:
        # Below the threshold, only callers with role-based read perm (i.e.
        # bulk-listing privilege) get matches — others see nothing.
        if not _has_unrestricted_perm(user, "read"):
            return []

    cap = _max_page_len()
    try:
        page_len_int = int(page_len) if page_len else cap
    except (TypeError, ValueError):
        page_len_int = cap
    page_len_int = max(1, min(page_len_int, cap))

    frappe.flags.vapt_in_user_autocomplete = True
    try:
        return _original(doctype, txt, searchfield, start, page_len_int, filters)
    finally:
        frappe.flags.vapt_in_user_autocomplete = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _required_ptype() -> str:
    return "select" if frappe.flags.get("vapt_in_user_autocomplete") else "read"


def _is_killed() -> bool:
    return bool((frappe.conf or {}).get("frappe_vapt_user_enumeration_disabled"))


def _min_chars() -> int:
    conf = (frappe.conf or {}).get("frappe_vapt_user_autocomplete_min_chars")
    if conf is None:
        return DEFAULT_AUTOCOMPLETE_MIN_CHARS
    try:
        return max(0, int(conf))
    except (TypeError, ValueError):
        return DEFAULT_AUTOCOMPLETE_MIN_CHARS


def _max_page_len() -> int:
    conf = (frappe.conf or {}).get("frappe_vapt_user_autocomplete_max_page_len")
    if conf is None:
        return DEFAULT_AUTOCOMPLETE_MAX_PAGE_LEN
    try:
        return max(1, int(conf))
    except (TypeError, ValueError):
        return DEFAULT_AUTOCOMPLETE_MAX_PAGE_LEN


def _has_unrestricted_perm(user: str, ptype: str) -> bool:
    """True if any role the user holds grants ``ptype`` on User without
    ``if_owner`` restriction.

    Frappe's ``has_permission`` with ``doc=None`` is too permissive for our
    purposes — it returns True if any role grants the perm with ``if_owner``,
    which would let an Employee user pass the doctype-level gate even though
    they can only read their own User row. We want the stricter sense: "does
    the user have a role-based, non-owner-restricted ``ptype`` on User?".
    """
    if user == "Administrator":
        return True
    try:
        from frappe.permissions import get_valid_perms
        perms = get_valid_perms(doctype="User", user=user) or []
    except Exception:
        return False
    for perm in perms:
        if perm.get(ptype) and not perm.get("if_owner"):
            return True
    return False
