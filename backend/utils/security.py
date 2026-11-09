import hmac
import re
import secrets
from functools import wraps

from flask import jsonify, request, session

from database.db import get_db_connection


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf_token():
    expected = session.get("csrf_token")
    submitted = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )
    if not submitted and request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict):
            submitted = data.get("csrf_token")

    return (
        isinstance(expected, str)
        and isinstance(submitted, str)
        and hmac.compare_digest(expected, submitted)
    )


def redact_sensitive_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Sensitive text must be a string.")

    sanitized = re.sub(
        r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        value,
    )
    sanitized = re.sub(
        r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"authorization|bearer|token|password|passwd|secret|private[_-]?key|"
        r"wallet[_-]?secret)\b\s*[:=]\s*[\"']?[^\"'\s,;&]+",
        r"\1=[REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",
        "Bearer [REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "[REDACTED]",
        sanitized,
    )
    return sanitized


def login_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if type(user_id) is not int or user_id <= 0:
            session.clear()
            return jsonify({
                "error": "Authentication required."
            }), 401

        with get_db_connection() as connection:
            user = connection.execute(
                "SELECT id, username, role, is_active FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

        if user is None or not user["is_active"]:
            session.clear()
            return jsonify({
                "error": "Authentication required."
            }), 401

        session["username"] = user["username"]
        session["role"] = user["role"]
        return view_function(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view_function):
        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):
            if session.get("role") not in allowed_roles:
                return jsonify({
                    "error": "You do not have permission to access this resource."
                }), 403

            return view_function(*args, **kwargs)

        return wrapped_view

    return decorator
