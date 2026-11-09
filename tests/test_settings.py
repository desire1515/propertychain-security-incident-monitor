import pytest
from werkzeug.security import check_password_hash

from backend.services.auth_service import authenticate_user, create_user
from backend.services.settings_service import (
    change_user_password,
    create_managed_analyst,
    get_managed_users,
    get_user_profile,
    update_managed_user,
)


def _session_as(client, user, role_override=None):
    with client.session_transaction() as session:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = role_override or user["role"]
        session["csrf_token"] = "test-csrf-token"


def _rows(database, query, parameters=()):
    return tuple(
        tuple(row) for row in database.execute(query, parameters).fetchall()
    )


def test_profile_page_displays_account_without_user_management(
    authenticated_client,
    test_user,
):
    response = authenticated_client.get("/settings")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert test_user["username"] in body
    assert "Admin" in body
    assert "My Profile" in body
    assert "System Information" in body
    assert "no verified Firebase adapter is active" in body
    assert "User Management" in body


def test_analyst_can_view_settings_but_cannot_manage_users(
    client,
    analyst,
    database,
):
    _session_as(client, analyst, role_override="admin")
    response = client.get("/settings")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert analyst["username"] in body
    assert "User Management" not in body

    before = _rows(database, "SELECT * FROM users ORDER BY id")
    before_audit = _rows(database, "SELECT * FROM system_audit_logs ORDER BY id")
    response = client.post(
        "/settings/users",
        data={
            "username": "forbidden-managed-user",
            "password": "valid-temporary-password",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 403
    assert _rows(database, "SELECT * FROM users ORDER BY id") == before
    assert _rows(database, "SELECT * FROM system_audit_logs ORDER BY id") == before_audit


def test_password_change_requires_current_password_and_audits_without_secret(
    test_user,
    authenticated_client,
    database,
):
    new_password = "new-secure-password-456"
    response = authenticated_client.post(
        "/settings/password",
        data={
            "current_password": test_user["password"],
            "new_password": new_password,
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Password changed successfully." in response.get_data(as_text=True)
    assert authenticate_user(test_user["username"], new_password) is not None
    password_log = database.execute(
        """
        SELECT details FROM system_audit_logs
        WHERE action = 'ACCOUNT_PASSWORD_CHANGED'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    assert new_password not in password_log["details"]
    stored_hash = database.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (test_user["id"],),
    ).fetchone()["password_hash"]
    assert check_password_hash(stored_hash, new_password)


@pytest.mark.parametrize(
    ("current_password", "new_password"),
    [
        ("wrong-current-password", "new-secure-password-789"),
        ("test-admin-password-123", "short"),
    ],
)
def test_password_change_rejects_bad_current_or_policy(
    test_user,
    authenticated_client,
    database,
    current_password,
    new_password,
):
    old_hash = database.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (test_user["id"],),
    ).fetchone()["password_hash"]
    audit_before = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs "
        "WHERE action = 'ACCOUNT_PASSWORD_CHANGED'"
    ).fetchone()[0]

    response = authenticated_client.post(
        "/settings/password",
        data={
            "current_password": current_password,
            "new_password": new_password,
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert database.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (test_user["id"],),
    ).fetchone()["password_hash"] == old_hash
    assert database.execute(
        "SELECT COUNT(*) FROM system_audit_logs "
        "WHERE action = 'ACCOUNT_PASSWORD_CHANGED'"
    ).fetchone()[0] == audit_before


def test_password_route_rejects_missing_csrf_without_writing(
    test_user,
    authenticated_client,
    database,
):
    before = database.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (test_user["id"],),
    ).fetchone()["password_hash"]
    response = authenticated_client.post(
        "/settings/password",
        data={
            "current_password": test_user["password"],
            "new_password": "another-secure-password",
        },
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (test_user["id"],),
    ).fetchone()["password_hash"] == before


def test_admin_can_create_update_and_deactivate_analyst_accounts(
    test_user,
    authenticated_client,
    database,
):
    response = authenticated_client.post(
        "/settings/users",
        data={
            "username": "managed-analyst",
            "password": "managed-analyst-password",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    created = database.execute(
        "SELECT id, role, is_active FROM users WHERE username = ?",
        ("managed-analyst",),
    ).fetchone()
    assert tuple(created[1:]) == ("analyst", 1)
    assert authenticate_user("managed-analyst", "managed-analyst-password")

    response = authenticated_client.post(
        f"/settings/users/{created['id']}",
        data={
            "role": "admin",
            "is_active": "1",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert database.execute(
        "SELECT role FROM users WHERE id = ?",
        (created["id"],),
    ).fetchone()["role"] == "admin"

    response = authenticated_client.post(
        f"/settings/users/{created['id']}",
        data={
            "role": "analyst",
            "is_active": "0",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    updated = database.execute(
        "SELECT role, is_active FROM users WHERE id = ?",
        (created["id"],),
    ).fetchone()
    assert tuple(updated) == ("analyst", 0)
    assert database.execute(
        """
        SELECT COUNT(*) FROM system_audit_logs
        WHERE user_id = ? AND action IN ('USER_CREATED', 'USER_ACCOUNT_UPDATED')
        """,
        (test_user["id"],),
    ).fetchone()[0] == 3


def test_settings_service_blocks_self_deactivation_and_last_admin_removal(
    test_user,
):
    with pytest.raises(ValueError, match="cannot deactivate or demote themselves"):
        update_managed_user(
            test_user["id"],
            role="admin",
            is_active=False,
            updated_by=test_user["id"],
        )
    with pytest.raises(ValueError, match="cannot deactivate or demote themselves"):
        update_managed_user(
            test_user["id"],
            role="analyst",
            is_active=True,
            updated_by=test_user["id"],
        )


def test_settings_services_enforce_admin_role_and_audit_updates(
    analyst,
    test_user,
    database,
):
    with pytest.raises(ValueError, match="active administrator"):
        get_managed_users(analyst["id"])
    with pytest.raises(ValueError, match="active administrator"):
        create_managed_analyst(
            "not-allowed-analyst",
            "valid-password-for-analyst",
            created_by=analyst["id"],
        )
    with pytest.raises(ValueError, match="active administrator"):
        update_managed_user(
            analyst["id"],
            role="analyst",
            is_active=False,
            updated_by=analyst["id"],
        )

    profile = get_user_profile(test_user["id"])
    assert profile["username"] == test_user["username"]
    assert profile["role"] == "admin"
    assert profile["is_active"] == 1
    assert database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'USER_ACCOUNT_UPDATED'"
    ).fetchone()[0] == 0


def test_user_management_routes_enforce_csrf_and_validate_input(
    test_user,
    authenticated_client,
    database,
):
    before = _rows(database, "SELECT * FROM users ORDER BY id")
    response = authenticated_client.post(
        "/settings/users",
        data={"username": "no-csrf-user", "password": "valid-password-value"},
    )
    assert response.status_code == 302
    assert _rows(database, "SELECT * FROM users ORDER BY id") == before

    response = authenticated_client.post(
        "/settings/users",
        data={
            "username": "short-password-user",
            "password": "short",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert _rows(database, "SELECT * FROM users ORDER BY id") == before

    with pytest.raises(ValueError, match="Invalid user role"):
        update_managed_user(
            test_user["id"],
            role="superuser",
            is_active=True,
            updated_by=test_user["id"],
        )
