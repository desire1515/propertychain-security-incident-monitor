import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

from database.db import get_db_connection

ALLOWED_USER_ROLES = {"admin", "analyst"}


def _require_admin(connection, actor_id):
    if type(actor_id) is not int or actor_id <= 0:
        raise ValueError("An active administrator is required.")
    actor = connection.execute(
        "SELECT id FROM users WHERE id = ? AND is_active = 1 AND role = 'admin'",
        (actor_id,),
    ).fetchone()
    if actor is None:
        raise ValueError("An active administrator is required.")


def _validate_username(username):
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username is required.")
    username = username.strip()
    if len(username) > 80:
        raise ValueError("Username cannot exceed 80 characters.")
    return username


def _validate_password(password):
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    if len(password) > 1024:
        raise ValueError("Password cannot exceed 1024 characters.")
    return password


def get_user_profile(user_id):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("An active user is required.")
    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT id, username, role, is_active, created_at
            FROM users WHERE id = ? AND is_active = 1
            """,
            (user_id,),
        ).fetchone()
    if row is None:
        raise ValueError("An active user is required.")
    return dict(row)


def change_user_password(user_id, current_password, new_password):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("An active user is required.")
    if not isinstance(current_password, str) or len(current_password) > 1024:
        raise ValueError("Current password is incorrect.")
    new_password = _validate_password(new_password)
    with get_db_connection() as connection:
        user = connection.execute(
            """
            SELECT password_hash FROM users
            WHERE id = ? AND is_active = 1
            """,
            (user_id,),
        ).fetchone()
        if user is None or not check_password_hash(
            user["password_hash"], current_password
        ):
            raise ValueError("Current password is incorrect.")

        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, 'ACCOUNT_PASSWORD_CHANGED', 'User changed their password.')
            """,
            (user_id,),
        )
        connection.commit()
    return True


def get_managed_users(actor_id):
    with get_db_connection() as connection:
        _require_admin(connection, actor_id)
        rows = connection.execute(
            """
            SELECT id, username, role, is_active, created_at
            FROM users
            ORDER BY username COLLATE NOCASE, id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def create_managed_analyst(username, password, created_by):
    username = _validate_username(username)
    password = _validate_password(password)
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_admin(connection, created_by)
        try:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, 'analyst')
                """,
                (username, generate_password_hash(password)),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("Username is already in use.") from error
        user_id = cursor.lastrowid
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, 'USER_CREATED', ?)
            """,
            (created_by, f"Analyst account ID {user_id} was created."),
        )
        connection.commit()
    return user_id


def update_managed_user(user_id, role, is_active, updated_by):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("Invalid user ID.")
    if role not in ALLOWED_USER_ROLES:
        raise ValueError("Invalid user role.")
    if type(is_active) is not bool:
        raise ValueError("Invalid account status.")

    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_admin(connection, updated_by)
        user = connection.execute(
            "SELECT id, username, role, is_active FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            raise ValueError("User not found.")

        if user_id == updated_by and (not is_active or role != "admin"):
            raise ValueError("Administrators cannot deactivate or demote themselves.")

        if user["role"] == "admin" and user["is_active"] and (
            role != "admin" or not is_active
        ):
            active_admin_count = connection.execute(
                """
                SELECT COUNT(*) AS count FROM users
                WHERE role = 'admin' AND is_active = 1
                """
            ).fetchone()["count"]
            if active_admin_count <= 1:
                raise ValueError("The last active administrator cannot be disabled or demoted.")

        if user["role"] == role and bool(user["is_active"]) == is_active:
            return False

        connection.execute(
            "UPDATE users SET role = ?, is_active = ? WHERE id = ?",
            (role, int(is_active), user_id),
        )
        details = (
            f"User account ID {user_id} ({user['username']}) updated: "
            f"role {user['role']} -> {role}; "
            f"active {int(bool(user['is_active']))} -> {int(is_active)}."
        )
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, 'USER_ACCOUNT_UPDATED', ?)
            """,
            (updated_by, details),
        )
        connection.commit()
    return True
