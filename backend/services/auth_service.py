import sqlite3

from flask import current_app, has_app_context
from werkzeug.security import generate_password_hash, check_password_hash

from backend.services.event_service import record_security_event
from database.db import get_db_connection


def _record_authentication_audit(user_id, action, details):
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, ?, ?)
            """,
            (user_id, action, details),
        )
        connection.commit()


def _record_failed_authentication_event():
    classification = (
        "TEST"
        if has_app_context() and current_app.config.get("TESTING")
        else "REAL"
    )
    record_security_event(
        source="PCSIRM Authentication",
        event_type="AUTHENTICATION_FAILED",
        severity="high",
        classification=classification,
        description="A login attempt was rejected.",
    )


def record_logout(user_id):
    if type(user_id) is not int or user_id <= 0:
        return

    with get_db_connection() as connection:
        user = connection.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            return

        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, 'AUTHENTICATION_LOGOUT', 'User logged out.')
            """,
            (user_id,),
        )
        connection.commit()


def create_user(username, password, role="analyst"):
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username and password are required.")

    normalized_username = username.strip()
    if len(normalized_username) > 80:
        raise ValueError("Username cannot exceed 80 characters.")

    if not isinstance(password, str) or not password:
        raise ValueError("Username and password are required.")

    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    if len(password) > 1024:
        raise ValueError("Password cannot exceed 1024 characters.")

    if role not in ("admin", "analyst"):
        raise ValueError("Invalid user role.")

    password_hash = generate_password_hash(password)

    try:
        with get_db_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
                """,
                (normalized_username, password_hash, role)
            )
            connection.commit()

        return True

    except sqlite3.IntegrityError as error:
        raise ValueError("Username is already in use.") from error


def authenticate_user(username, password):
    if not isinstance(username, str) or not isinstance(password, str):
        _record_authentication_audit(
            None,
            "AUTHENTICATION_FAILED",
            "Login rejected because the submitted credentials were malformed.",
        )
        _record_failed_authentication_event()
        return None

    normalized_username = username.strip()
    if not normalized_username:
        _record_authentication_audit(
            None,
            "AUTHENTICATION_FAILED",
            "Login rejected because the submitted username was empty.",
        )
        _record_failed_authentication_event()
        return None

    if len(password) > 1024:
        _record_authentication_audit(
            None,
            "AUTHENTICATION_FAILED",
            "Login rejected because the submitted password exceeded the allowed length.",
        )
        _record_failed_authentication_event()
        return None

    with get_db_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username, password_hash, role, is_active
            FROM users
            WHERE username = ?
            """,
            (normalized_username,)
        ).fetchone()

    if user is None:
        _record_authentication_audit(
            None,
            "AUTHENTICATION_FAILED",
            "Login rejected for an unknown account.",
        )
        _record_failed_authentication_event()
        return None

    if not user["is_active"]:
        _record_authentication_audit(
            user["id"],
            "AUTHENTICATION_FAILED",
            "Login rejected for an inactive account.",
        )
        _record_failed_authentication_event()
        return None

    if not check_password_hash(user["password_hash"], password):
        _record_authentication_audit(
            user["id"],
            "AUTHENTICATION_FAILED",
            "Login rejected because the password did not match.",
        )
        _record_failed_authentication_event()
        return None

    _record_authentication_audit(
        user["id"],
        "AUTHENTICATION_SUCCEEDED",
        "User authenticated successfully.",
    )
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }
