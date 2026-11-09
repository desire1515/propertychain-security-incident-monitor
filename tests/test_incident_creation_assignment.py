import pytest

from backend.services.auth_service import create_user
from backend.services.event_service import record_security_event
from backend.services.incident_service import (
    assign_incident,
    create_incident,
    get_incident_by_event_reference,
    get_incident_by_reference,
)


def _set_session(client, user):
    with client.session_transaction() as session:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["csrf_token"] = "test-csrf-token"


def _create_event(classification="REAL"):
    return record_security_event(
        source="Incident workflow test source",
        event_type="ACCESS_DENIED",
        severity="high",
        classification=classification,
        description="A security event for incident workflow tests.",
    )


def _create_unassigned_incident(test_user):
    return create_incident(
        title="Assignment workflow test",
        description="Incident created for assignment tests.",
        severity="medium",
        classification="TEST",
        created_by=test_user["id"],
    )


def test_event_list_offers_creation_and_route_creates_incident(
    authenticated_client,
    test_user,
    database,
):
    event_reference = _create_event()
    events_page = authenticated_client.get("/events")
    assert f"/events/{event_reference}/incidents/new" in events_page.get_data(
        as_text=True
    )

    form_page = authenticated_client.get(
        f"/events/{event_reference}/incidents/new"
    )
    assert form_page.status_code == 200
    assert "Create Incident" in form_page.get_data(as_text=True)

    response = authenticated_client.post(
        f"/events/{event_reference}/incidents/new",
        data={
            "title": "Operator-reviewed incident",
            "description": "Reviewed event and opened an investigation.",
            "severity": "critical",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    incident = get_incident_by_event_reference(event_reference)
    assert incident["title"] == "Operator-reviewed incident"
    incident_row = database.execute(
        "SELECT * FROM incidents WHERE incident_reference = ?",
        (incident["incident_reference"],),
    ).fetchone()
    assert incident_row["severity"] == "critical"
    assert incident_row["classification"] == "REAL"
    assert incident_row["source_event_id"] is not None
    timeline = database.execute(
        "SELECT activity FROM incident_timeline WHERE incident_id = ?",
        (incident_row["id"],),
    ).fetchall()
    audit = database.execute(
        """
        SELECT user_id, action FROM system_audit_logs
        WHERE details LIKE ?
        """,
        (f"%{incident['incident_reference']}%",),
    ).fetchall()
    assert [row["activity"] for row in timeline] == ["Incident created"]
    assert any(
        row["user_id"] == test_user["id"] and row["action"] == "INCIDENT_CREATED"
        for row in audit
    )


def test_event_incident_creation_rejects_duplicate_and_missing_event(
    authenticated_client,
    test_user,
):
    event_reference = _create_event()
    first = authenticated_client.post(
        f"/events/{event_reference}/incidents/new",
        data={
            "title": "First incident",
            "description": "First submission.",
            "severity": "high",
            "csrf_token": "test-csrf-token",
        },
    )
    assert first.status_code == 302
    incident = get_incident_by_event_reference(event_reference)

    duplicate = authenticated_client.post(
        f"/events/{event_reference}/incidents/new",
        data={
            "title": "Duplicate incident",
            "description": "Duplicate submission.",
            "severity": "high",
            "csrf_token": "test-csrf-token",
        },
    )
    assert duplicate.status_code == 302
    assert duplicate.headers["Location"].endswith(
        f"/incidents/{incident['incident_reference']}"
    )

    missing = authenticated_client.get("/events/EVT-NOT-FOUND/incidents/new")
    assert missing.status_code == 302
    assert get_incident_by_event_reference("EVT-NOT-FOUND") is None


def test_event_incident_creation_rejects_invalid_input_without_writing(
    authenticated_client,
    database,
):
    event_reference = _create_event()
    before = database.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    response = authenticated_client.post(
        f"/events/{event_reference}/incidents/new",
        data={
            "title": "",
            "description": "Invalid title.",
            "severity": "immediate",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 400
    assert database.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == before


def test_event_incident_creation_requires_csrf(authenticated_client, database):
    event_reference = _create_event()
    before = database.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

    response = authenticated_client.post(
        f"/events/{event_reference}/incidents/new",
        data={
            "title": "CSRF incident",
            "description": "Must not be created.",
            "severity": "high",
        },
    )
    assert response.status_code == 302
    assert database.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == before


def test_assignment_and_reassignment_are_audited_and_timed(
    test_user,
    analyst,
    database,
):
    second_analyst = create_user(
        "second-incident-analyst",
        "second-analyst-password-123",
        role="analyst",
    )
    second_analyst_id = database.execute(
        "SELECT id FROM users WHERE username = ?",
        ("second-incident-analyst",),
    ).fetchone()["id"]
    reference = _create_unassigned_incident(test_user)

    assert assign_incident(reference, analyst["id"], test_user["id"]) is True
    assert assign_incident(reference, second_analyst_id, test_user["id"]) is True
    assert assign_incident(reference, None, test_user["id"]) is True
    assert assign_incident(reference, None, test_user["id"]) is False

    incident = get_incident_by_reference(reference)
    assert incident["assigned_to"] is None
    timeline = database.execute(
        """
        SELECT activity, details FROM incident_timeline
        WHERE incident_id = ? ORDER BY id
        """,
        (incident["id"],),
    ).fetchall()
    assignment_timeline = [row["activity"] for row in timeline[1:]]
    assert assignment_timeline == [
        "Incident assigned",
        "Incident reassigned",
        "Incident unassigned",
    ]
    audit = database.execute(
        """
        SELECT user_id, action FROM system_audit_logs
        WHERE action IN ('INCIDENT_ASSIGNED', 'INCIDENT_REASSIGNED', 'INCIDENT_UNASSIGNED')
        ORDER BY id
        """
    ).fetchall()
    assert [(row["user_id"], row["action"]) for row in audit] == [
        (test_user["id"], "INCIDENT_ASSIGNED"),
        (test_user["id"], "INCIDENT_REASSIGNED"),
        (test_user["id"], "INCIDENT_UNASSIGNED"),
    ]


def test_assignment_rejects_inactive_missing_and_non_analyst_targets(
    test_user,
    analyst,
    database,
):
    reference = _create_unassigned_incident(test_user)
    database.execute("UPDATE users SET is_active = 0 WHERE id = ?", (analyst["id"],))
    database.commit()
    with pytest.raises(ValueError, match="inactive"):
        assign_incident(reference, analyst["id"], test_user["id"])
    with pytest.raises(ValueError, match="inactive"):
        assign_incident(reference, 99999, test_user["id"])
    with pytest.raises(ValueError, match="not an analyst"):
        assign_incident(reference, test_user["id"], test_user["id"])


def test_only_administrators_can_assign_through_service_and_route(
    test_user,
    analyst,
    client,
    database,
):
    reference = _create_unassigned_incident(test_user)
    with pytest.raises(ValueError, match="active administrator"):
        assign_incident(reference, analyst["id"], analyst["id"])

    _set_session(client, analyst)
    before = database.execute(
        "SELECT assigned_to FROM incidents WHERE incident_reference = ?",
        (reference,),
    ).fetchone()["assigned_to"]
    response = client.post(
        f"/incidents/{reference}/assignment",
        data={
            "assigned_to": str(analyst["id"]),
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT assigned_to FROM incidents WHERE incident_reference = ?",
        (reference,),
    ).fetchone()["assigned_to"] == before


def test_assignment_route_requires_csrf_and_admin_session(
    authenticated_client,
    test_user,
    analyst,
    database,
):
    reference = _create_unassigned_incident(test_user)
    response = authenticated_client.post(
        f"/incidents/{reference}/assignment",
        data={"assigned_to": str(analyst["id"])},
    )
    assert response.status_code == 302
    assert get_incident_by_reference(reference)["assigned_to"] is None

    response = authenticated_client.post(
        f"/incidents/{reference}/assignment",
        data={
            "assigned_to": str(analyst["id"]),
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    assert get_incident_by_reference(reference)["assigned_to"] == analyst["id"]


def test_assignment_selector_is_admin_only_and_shows_active_analysts(
    authenticated_client,
    test_user,
    analyst,
    client,
):
    reference = _create_unassigned_incident(test_user)
    detail = authenticated_client.get(f"/incidents/{reference}").get_data(
        as_text=True
    )
    assert "Assign to analyst" in detail
    assert analyst["username"] in detail

    _set_session(client, analyst)
    analyst_detail = client.get(f"/incidents/{reference}").get_data(as_text=True)
    assert "Assign to analyst" not in analyst_detail
