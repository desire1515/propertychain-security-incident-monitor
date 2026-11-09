import sqlite3
from pathlib import Path

import pytest

from backend.services.auth_service import authenticate_user
from backend.services.event_service import (
    get_security_events,
    record_security_event,
)
from backend.services.incident_service import (
    create_incident,
    create_incident_from_event,
    get_incident_by_reference,
    update_incident_status,
)
from config import Config


@pytest.mark.parametrize(
    "path",
    ["/dashboard", "/events", "/incidents", "/incidents/INC-MISSING"],
)
def test_protected_routes_reject_unauthenticated_requests(client, path):
    response = client.get(path)

    assert response.status_code == 401
    assert response.get_json()["error"] == "Authentication required."


def test_incident_status_route_rejects_unauthenticated_request(client):
    response = client.post(
        "/incidents/INC-MISSING/status",
        data={"status": "resolved"},
    )

    assert response.status_code == 401


def test_login_succeeds_with_valid_credentials(client, test_user):
    client.get("/auth/signin")
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]

    response = client.post(
        "/auth/login",
        json={
            "username": test_user["username"],
            "password": test_user["password"],
        },
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    assert response.get_json()["user"]["username"] == test_user["username"]


def test_browser_login_succeeds_with_valid_credentials(client, test_user):
    client.get("/auth/signin")
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]

    response = client.post(
        "/auth/signin",
        data={
            "username": test_user["username"],
            "password": test_user["password"],
            "csrf_token": csrf_token,
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_login_fails_with_invalid_credentials(client):
    client.get("/auth/signin")
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]

    response = client.post(
        "/auth/login",
        json={"username": "not-a-user", "password": "incorrect"},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 401


@pytest.mark.parametrize("csrf_token", [None, "invalid-csrf-token"])
def test_login_rejects_missing_or_invalid_csrf(client, test_user, csrf_token):
    client.get("/auth/signin")
    headers = {"X-CSRFToken": csrf_token} if csrf_token else {}

    response = client.post(
        "/auth/login",
        json={
            "username": test_user["username"],
            "password": test_user["password"],
        },
        headers=headers,
    )

    assert response.status_code == 400
    assert "security token" in response.get_json()["error"].lower()


def test_inactive_users_cannot_log_in(client, test_user, database):
    database.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (test_user["id"],),
    )
    database.commit()

    assert authenticate_user(
        test_user["username"], test_user["password"]
    ) is None
    client.get("/auth/signin")
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]

    response = client.post(
        "/auth/login",
        json={
            "username": test_user["username"],
            "password": test_user["password"],
        },
        headers={"X-CSRFToken": csrf_token},
    )
    assert response.status_code == 401


def test_logout_clears_session(client, test_user):
    with client.session_transaction() as session:
        session["user_id"] = test_user["id"]
        session["username"] = test_user["username"]
        session["role"] = test_user["role"]
        session["csrf_token"] = "test-csrf-token"

    response = client.post(
        "/auth/logout",
        json={},
        headers={"X-CSRFToken": "test-csrf-token"},
    )

    assert response.status_code == 200
    assert response.get_json()["message"] == "Logout successful."
    with client.session_transaction() as session:
        assert not session


def test_logout_is_audited_for_authenticated_user(client, test_user, database):
    with client.session_transaction() as session:
        session["user_id"] = test_user["id"]
        session["username"] = test_user["username"]
        session["role"] = test_user["role"]
        session["csrf_token"] = "test-csrf-token"

    response = client.post(
        "/auth/logout",
        data={"csrf_token": "test-csrf-token"},
    )

    assert response.status_code == 302
    audit = database.execute(
        """
        SELECT user_id, action, details
        FROM system_audit_logs
        WHERE action = 'AUTHENTICATION_LOGOUT'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    assert audit["user_id"] == test_user["id"]
    assert audit["details"] == "User logged out."


def test_logout_rejects_invalid_csrf_without_clearing_session(client, test_user):
    with client.session_transaction() as session:
        session["user_id"] = test_user["id"]
        session["username"] = test_user["username"]
        session["role"] = test_user["role"]
        session["csrf_token"] = "valid-csrf-token"

    response = client.post(
        "/auth/logout",
        json={},
        headers={"X-CSRFToken": "invalid-csrf-token"},
    )

    assert response.status_code == 400
    with client.session_transaction() as session:
        assert session["user_id"] == test_user["id"]


def test_inactive_session_is_revoked_on_protected_request(
    client,
    test_user,
    database,
):
    with client.session_transaction() as session:
        session["user_id"] = test_user["id"]
        session["username"] = test_user["username"]
        session["role"] = test_user["role"]
        session["csrf_token"] = "test-csrf-token"

    database.execute(
        "UPDATE users SET is_active = 0 WHERE id = ?",
        (test_user["id"],),
    )
    database.commit()

    response = client.get("/dashboard")

    assert response.status_code == 401
    with client.session_transaction() as session:
        assert not session


def test_authentication_audit_never_records_submitted_password(
    test_user,
    database,
):
    assert authenticate_user(
        test_user["username"],
        "incorrect-password-value",
    ) is None

    audit = database.execute(
        """
        SELECT user_id, action, details
        FROM system_audit_logs
        WHERE action = 'AUTHENTICATION_FAILED'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    assert audit["user_id"] == test_user["id"]
    assert "incorrect-password-value" not in audit["details"]


def test_security_event_can_be_recorded_and_retrieved():
    reference = record_security_event(
        source="Test Source",
        event_type="ACCESS_REVIEW",
        severity="medium",
        classification="TEST",
        description="A recorded test event.",
        raw_data={"test": True},
    )

    events = get_security_events()
    event = next(item for item in events if item["event_reference"] == reference)

    assert event["event_type"] == "ACCESS_REVIEW"
    assert event["severity"] == "medium"
    assert event["classification"] == "TEST"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("severity", "urgent", "Invalid event severity."),
        ("classification", "PRODUCTION", "Invalid event classification."),
    ],
)
def test_security_event_rejects_invalid_values(field, value, message):
    data = {
        "source": "Test Source",
        "event_type": "TEST_EVENT",
        "severity": "low",
        "classification": "TEST",
        "description": "A test event.",
    }
    data[field] = value

    with pytest.raises(ValueError, match=message):
        record_security_event(**data)


def test_event_list_filters_results(authenticated_client):
    matching_reference = record_security_event(
        source="Filter Match",
        event_type="MATCHING_EVENT",
        severity="critical",
        classification="REAL",
        description="Unique phrase for filter match.",
    )
    other_reference = record_security_event(
        source="Filter Other",
        event_type="OTHER_EVENT",
        severity="low",
        classification="TEST",
        description="An event that should not match.",
    )

    response = authenticated_client.get(
        "/events?severity=critical&classification=REAL&search=Unique%20phrase"
    )
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert matching_reference in body
    assert other_reference not in body


def test_incident_creation_records_timeline_and_audit(
    test_user, database
):
    reference = create_incident(
        title="Test incident",
        description="Incident created by an isolated test.",
        severity="high",
        classification="TEST",
        assigned_to=test_user["id"],
        created_by=test_user["id"],
    )

    incident = get_incident_by_reference(reference)
    timeline = database.execute(
        "SELECT activity FROM incident_timeline WHERE incident_id = ?",
        (incident["id"],),
    ).fetchall()
    audit = database.execute(
        "SELECT action FROM system_audit_logs WHERE details LIKE ?",
        (f"%{reference}%",),
    ).fetchall()

    assert incident["title"] == "Test incident"
    assert incident["assigned_username"] == test_user["username"]
    assert [row["activity"] for row in timeline] == ["Incident created"]
    assert [row["action"] for row in audit] == ["INCIDENT_CREATED"]


def test_incident_can_be_created_from_security_event(test_event, test_user):
    reference = create_incident_from_event(
        test_event["event_reference"],
        assigned_to=test_user["id"],
        created_by=test_user["id"],
    )
    incident = get_incident_by_reference(reference)

    assert incident["source_event_id"] == test_event["id"]
    assert incident["source_event_reference"] == test_event["event_reference"]
    assert incident["severity"] == test_event["severity"]


def test_duplicate_event_to_incident_link_is_rejected(test_event, test_user):
    create_incident_from_event(
        test_event["event_reference"],
        created_by=test_user["id"],
    )

    with pytest.raises(ValueError, match="already be linked"):
        create_incident_from_event(
            test_event["event_reference"],
            created_by=test_user["id"],
        )


def test_incident_status_update_records_timeline_and_audit(
    test_user, database
):
    reference = create_incident(
        title="Status transition incident",
        description=None,
        severity="medium",
        classification="SIMULATED",
        created_by=test_user["id"],
    )
    incident_id = get_incident_by_reference(reference)["id"]

    assert update_incident_status(reference, "investigating", test_user["id"])
    updated = get_incident_by_reference(reference)
    timeline = database.execute(
        "SELECT activity, details FROM incident_timeline "
        "WHERE incident_id = ? ORDER BY id",
        (incident_id,),
    ).fetchall()
    audit = database.execute(
        "SELECT action FROM system_audit_logs WHERE details LIKE ?",
        (f"{reference}:%",),
    ).fetchall()

    assert updated["status"] == "investigating"
    assert timeline[-1]["activity"] == "Status changed"
    assert "open to investigating" in timeline[-1]["details"]
    assert [row["action"] for row in audit] == ["INCIDENT_STATUS_UPDATED"]


def test_invalid_incident_status_is_rejected(test_user):
    reference = create_incident(
        title="Invalid transition incident",
        description=None,
        severity="low",
        classification="TEST",
        created_by=test_user["id"],
    )

    with pytest.raises(ValueError, match="Invalid incident status"):
        update_incident_status(reference, "not-a-status", test_user["id"])


def test_missing_incidents_are_handled():
    assert get_incident_by_reference("INC-NOT-FOUND") is None

    with pytest.raises(ValueError, match="Incident not found"):
        update_incident_status("INC-NOT-FOUND", "resolved")


def test_unchanged_status_does_not_add_duplicate_activity(
    test_user, database
):
    reference = create_incident(
        title="Unchanged status incident",
        description=None,
        severity="low",
        classification="TEST",
        created_by=test_user["id"],
    )
    incident_id = get_incident_by_reference(reference)["id"]
    timeline_before = database.execute(
        "SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()[0]
    audit_before = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE details LIKE ?",
        (f"%{reference}%",),
    ).fetchone()[0]

    assert not update_incident_status(reference, "open", test_user["id"])

    timeline_after = database.execute(
        "SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()[0]
    audit_after = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE details LIKE ?",
        (f"%{reference}%",),
    ).fetchone()[0]
    assert timeline_after == timeline_before
    assert audit_after == audit_before


def test_authenticated_incident_list_and_detail_render(
    authenticated_client, test_event, test_user
):
    reference = create_incident_from_event(
        test_event["event_reference"],
        assigned_to=test_user["id"],
        created_by=test_user["id"],
    )

    listing = authenticated_client.get("/incidents")
    detail = authenticated_client.get(f"/incidents/{reference}")
    detail_body = detail.get_data(as_text=True)

    assert listing.status_code == 200
    assert reference in listing.get_data(as_text=True)
    assert detail.status_code == 200
    assert reference in detail_body
    assert test_event["event_reference"] in detail_body
    assert "Incident created" in detail_body


def test_incident_status_route_accepts_valid_update(
    authenticated_client, test_user
):
    reference = create_incident(
        title="Route status update",
        description=None,
        severity="high",
        classification="TEST",
        created_by=test_user["id"],
    )

    response = authenticated_client.post(
        f"/incidents/{reference}/status",
        data={"status": "contained", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Incident status updated successfully." in response.get_data(
        as_text=True
    )
    assert get_incident_by_reference(reference)["status"] == "contained"


def test_incident_status_route_handles_invalid_update(
    authenticated_client, test_user
):
    reference = create_incident(
        title="Invalid route status update",
        description=None,
        severity="high",
        classification="TEST",
        created_by=test_user["id"],
    )

    response = authenticated_client.post(
        f"/incidents/{reference}/status",
        data={"status": "invalid", "csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Please choose a valid incident status." in response.get_data(
        as_text=True
    )
    assert get_incident_by_reference(reference)["status"] == "open"


@pytest.mark.parametrize("csrf_token", [None, "invalid-csrf-token"])
def test_incident_status_route_rejects_missing_or_invalid_csrf(
    authenticated_client,
    test_user,
    csrf_token,
):
    reference = create_incident(
        title="CSRF protected incident",
        description=None,
        severity="medium",
        classification="TEST",
        created_by=test_user["id"],
    )
    data = {"status": "contained"}
    if csrf_token is not None:
        data["csrf_token"] = csrf_token

    response = authenticated_client.post(
        f"/incidents/{reference}/status",
        data=data,
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert get_incident_by_reference(reference)["status"] == "open"


def test_missing_incident_route_redirects_to_list(authenticated_client):
    response = authenticated_client.get(
        "/incidents/INC-NOT-FOUND",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert "Incident Management" in response.get_data(as_text=True)


def test_all_regression_endpoints_remain_available(
    client, test_user
):
    health_response = client.get("/health")
    assert health_response.status_code == 200
    assert health_response.headers["X-Content-Type-Options"] == "nosniff"
    assert health_response.headers["X-Frame-Options"] == "DENY"
    assert client.get("/").status_code == 200
    assert client.get("/auth/signin").status_code == 200
    with client.session_transaction() as session:
        csrf_token = session["csrf_token"]

    login_response = client.post(
        "/auth/login",
        json={
            "username": test_user["username"],
            "password": test_user["password"],
        },
        headers={"X-CSRFToken": csrf_token},
    )
    assert login_response.status_code == 200
    assert client.get("/auth/me").status_code == 200
    assert client.get("/dashboard").status_code == 200
    assert client.get("/events").status_code == 200
    assert client.get("/incidents").status_code == 200
    assert client.post(
        "/auth/logout",
        json={},
        headers={"X-CSRFToken": login_response.get_json()["csrf_token"]},
    ).status_code == 200


def test_secure_cookie_mode_adds_https_transport_header(client, app):
    app.config["SESSION_COOKIE_SECURE"] = True
    response = client.get("/health")

    assert "Strict-Transport-Security" in response.headers
    assert "Secure" in response.headers.get("Set-Cookie", "")


def test_test_database_is_isolated_from_development_database(
    app, database, test_user, test_event
):
    test_database_path = Path(
        database.execute("PRAGMA database_list").fetchone()["file"]
    ).resolve()
    development_database_path = Path(Config.DATABASE_PATH).resolve()
    assert test_database_path != development_database_path

    table_names = {
        row["name"]
        for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    assert {"users", "security_events", "incidents", "incident_timeline"} <= (
        table_names
    )

    reference = create_incident_from_event(
        test_event["event_reference"],
        created_by=test_user["id"],
    )

    development = sqlite3.connect(
        f"{development_database_path.as_uri()}?mode=ro",
        uri=True,
    )
    try:
        assert development.execute(
            "SELECT COUNT(*) FROM users WHERE username = ?",
            (test_user["username"],),
        ).fetchone()[0] == 0
        assert development.execute(
            "SELECT COUNT(*) FROM security_events WHERE event_reference = ?",
            (test_event["event_reference"],),
        ).fetchone()[0] == 0
        assert development.execute(
            "SELECT COUNT(*) FROM incidents WHERE incident_reference = ?",
            (reference,),
        ).fetchone()[0] == 0
        assert development.execute(
            """
            SELECT COUNT(*)
            FROM incident_timeline t
            JOIN incidents i ON i.id = t.incident_id
            WHERE i.incident_reference = ?
            """,
            (reference,),
        ).fetchone()[0] == 0
    finally:
        development.close()


def test_development_database_guard_captured_baseline(
    development_database_guard,
):
    snapshot = development_database_guard
    assert snapshot["exists"]
    assert snapshot["modified_ns"] is not None
    assert set(snapshot["rows"]) == {
        "users",
        "security_events",
        "incidents",
        "incident_timeline",
        "system_audit_logs",
        "monitoring_sources",
        "detection_rules",
        "detection_rule_executions",
        "detection_alerts",
        "simulation_runs",
        "incident_evidence",
        "incident_actions",
    }
