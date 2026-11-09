import pytest

from backend.services.event_service import record_security_event
from backend.services.incident_service import (
    add_incident_action,
    add_incident_evidence,
    assign_incident,
    create_incident,
    create_incident_from_event,
    get_incident_by_reference,
    update_incident_action_status,
    update_incident_status,
)


def _session_as(client, user, role_override=None):
    with client.session_transaction() as session:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = role_override or user["role"]
        session["csrf_token"] = "test-csrf-token"


def _create_incident(admin):
    return create_incident(
        title="Role authorization incident",
        description="Incident used to verify role permissions.",
        severity="high",
        classification="TEST",
        created_by=admin["id"],
    )


def _create_action(reference, admin, status=None):
    incident_id = get_incident_by_reference(reference)["id"]
    action_id = add_incident_action(
        incident_id,
        "RECOMMENDATION",
        "Review access records and document findings.",
        performed_by=admin["id"],
    )
    if status:
        if status == "approved":
            update_incident_action_status(action_id, "approved", admin["id"])
        elif status == "in_progress":
            update_incident_action_status(action_id, "approved", admin["id"])
            update_incident_action_status(action_id, "in_progress", admin["id"])
    return action_id


def _protected_state(database):
    state = {}
    for table in (
        "incidents",
        "incident_evidence",
        "incident_actions",
        "incident_timeline",
        "system_audit_logs",
    ):
        state[table] = tuple(
            tuple(row)
            for row in database.execute(
                f"SELECT * FROM {table} ORDER BY id"
            ).fetchall()
        )
    return state


def test_analyst_http_posts_cannot_change_admin_only_incident_records(
    test_user,
    analyst,
    client,
    database,
):
    reference = _create_incident(test_user)
    proposed_action = _create_action(reference, test_user)
    active_action = _create_action(reference, test_user, status="in_progress")
    _session_as(client, analyst, role_override="admin")
    before = _protected_state(database)

    requests = (
        (
            f"/incidents/{reference}/status",
            {"status": "contained"},
        ),
        (
            f"/incidents/{reference}/assignment",
            {"assigned_to": str(analyst["id"])},
        ),
        (
            f"/incidents/{reference}/actions/{proposed_action}/status",
            {"status": "approved"},
        ),
        (
            f"/incidents/{reference}/actions/{proposed_action}/status",
            {"status": "cancelled"},
        ),
        (
            f"/incidents/{reference}/actions/{active_action}/status",
            {"status": "completed"},
        ),
    )
    for path, data in requests:
        response = client.post(
            path,
            data={**data, "csrf_token": "test-csrf-token"},
        )
        assert response.status_code == 302
        assert _protected_state(database) == before


def test_analyst_direct_service_calls_cannot_bypass_authorization(
    test_user,
    analyst,
    database,
):
    reference = _create_incident(test_user)
    incident_id = get_incident_by_reference(reference)["id"]
    proposed_action = _create_action(reference, test_user)
    active_action = _create_action(reference, test_user, status="in_progress")
    simulation_action = add_incident_action(
        incident_id,
        "SIMULATION",
        "Controlled simulation metadata only.",
        performed_by=test_user["id"],
    )
    update_incident_action_status(
        simulation_action,
        "approved",
        updated_by=test_user["id"],
    )
    before = _protected_state(database)

    denied_calls = (
        lambda: assign_incident(reference, analyst["id"], analyst["id"]),
        lambda: update_incident_status(reference, "contained", analyst["id"]),
        lambda: update_incident_action_status(
            proposed_action, "approved", analyst["id"]
        ),
        lambda: update_incident_action_status(
            proposed_action, "cancelled", analyst["id"]
        ),
        lambda: update_incident_action_status(
            active_action, "completed", analyst["id"]
        ),
        lambda: update_incident_action_status(
            active_action, "cancelled", analyst["id"]
        ),
        lambda: update_incident_action_status(
            simulation_action, "in_progress", analyst["id"]
        ),
    )
    for operation in denied_calls:
        with pytest.raises(ValueError):
            operation()
        assert _protected_state(database) == before

    assert incident_id > 0


def test_analyst_can_view_create_incidents_register_evidence_and_track_work(
    analyst,
    test_user,
    client,
    database,
):
    reference = _create_incident(test_user)
    approved_action = _create_action(reference, test_user, status="approved")
    event_reference = record_security_event(
        "Role workflow source",
        "AUTHENTICATION_FAILED",
        "high",
        "TEST",
        "Test event created for analyst incident workflow.",
    )
    _session_as(client, analyst)

    assert client.get("/incidents").status_code == 200
    assert client.get(f"/incidents/{reference}").status_code == 200

    created = client.post(
        f"/events/{event_reference}/incidents/new",
        data={
            "title": "Analyst-created incident",
            "description": "Created by an analyst.",
            "severity": "high",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert created.status_code == 200
    created_incident = database.execute(
        "SELECT id, incident_reference FROM incidents WHERE source_event_id = "
        "(SELECT id FROM security_events WHERE event_reference = ?)",
        (event_reference,),
    ).fetchone()
    assert created_incident["incident_reference"] in created.get_data(
        as_text=True
    )

    response = client.post(
        f"/incidents/{reference}/evidence",
        data={
            "evidence_type": "LOG",
            "description": "Analyst-collected evidence.",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    response = client.post(
        f"/incidents/{reference}/actions",
        data={
            "action_type": "RECOMMENDATION",
            "description": "Analyst recommendation for review.",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    response = client.post(
        f"/incidents/{reference}/actions/{approved_action}/status",
        data={
            "status": "in_progress",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT action_status FROM incident_actions WHERE id = ?",
        (approved_action,),
    ).fetchone()["action_status"] == "in_progress"

    detail = client.get(f"/incidents/{reference}").get_data(as_text=True)
    assert "Add Evidence Record" in detail
    assert "Record Recommendation" in detail
    assert "Update Incident Status" not in detail
    assert "Assign to analyst" not in detail
    assert "Approve recommendation" not in detail
    assert "Mark completed" not in detail
    assert "Cancel" not in detail


def test_analyst_direct_service_calls_allow_evidence_and_recommendations(
    analyst,
    test_user,
):
    reference = _create_incident(test_user)
    incident_id = get_incident_by_reference(reference)["id"]
    event_reference = record_security_event(
        "Direct service role test",
        "DIRECT_SERVICE_TEST_EVENT",
        "low",
        "TEST",
        "Direct analyst incident creation test.",
    )
    created_reference = create_incident_from_event(
        event_reference,
        created_by=analyst["id"],
    )
    assert (
        get_incident_by_reference(created_reference)["source_event_reference"]
        == event_reference
    )
    with pytest.raises(ValueError, match="Only administrators may assign"):
        create_incident(
            "Analyst cannot assign at creation",
            None,
            "low",
            "TEST",
            assigned_to=analyst["id"],
            created_by=analyst["id"],
        )

    evidence_id = add_incident_evidence(
        incident_id,
        "REFERENCE",
        "Analyst evidence reference.",
        collected_by=analyst["id"],
    )
    action_id = add_incident_action(
        incident_id,
        "SIMULATION",
        "Record controlled simulation metadata only.",
        performed_by=analyst["id"],
    )
    assert evidence_id > 0
    assert action_id > 0


def test_analyst_can_record_simulation_metadata_through_route(
    analyst,
    test_user,
    client,
    database,
):
    reference = _create_incident(test_user)
    incident_id = get_incident_by_reference(reference)["id"]
    _session_as(client, analyst)

    response = client.post(
        f"/incidents/{reference}/actions",
        data={
            "action_type": "SIMULATION",
            "description": "Controlled simulation metadata only.",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    record = database.execute(
        "SELECT action_type, performed_by FROM incident_actions "
        "WHERE incident_id = ?",
        (incident_id,),
    ).fetchone()
    assert tuple(record) == ("SIMULATION", analyst["id"])


def test_administrator_retains_incident_assignment_status_and_action_controls(
    test_user,
    analyst,
    authenticated_client,
    database,
):
    reference = _create_incident(test_user)
    proposed_action = _create_action(reference, test_user)
    active_action = _create_action(reference, test_user, status="in_progress")

    assert authenticated_client.get(f"/incidents/{reference}").status_code == 200
    response = authenticated_client.post(
        f"/incidents/{reference}/status",
        data={"status": "investigating", "csrf_token": "test-csrf-token"},
    )
    assert response.status_code == 302
    response = authenticated_client.post(
        f"/incidents/{reference}/assignment",
        data={
            "assigned_to": str(analyst["id"]),
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    response = authenticated_client.post(
        f"/incidents/{reference}/actions/{proposed_action}/status",
        data={"status": "approved", "csrf_token": "test-csrf-token"},
    )
    assert response.status_code == 302
    response = authenticated_client.post(
        f"/incidents/{reference}/actions/{active_action}/status",
        data={"status": "completed", "csrf_token": "test-csrf-token"},
    )
    assert response.status_code == 302
    cancelled_action = _create_action(reference, test_user)
    response = authenticated_client.post(
        f"/incidents/{reference}/actions/{cancelled_action}/status",
        data={"status": "cancelled", "csrf_token": "test-csrf-token"},
    )
    assert response.status_code == 302

    incident = get_incident_by_reference(reference)
    assert incident["status"] == "investigating"
    assert incident["assigned_to"] == analyst["id"]
    statuses = {
        row["id"]: row["action_status"]
        for row in database.execute(
            "SELECT id, action_status FROM incident_actions WHERE incident_id = ?",
            (incident["id"],),
        ).fetchall()
    }
    assert statuses[proposed_action] == "approved"
    assert statuses[active_action] == "completed"
    assert statuses[cancelled_action] == "cancelled"


def test_analyst_cannot_complete_even_if_ui_is_bypassed(
    analyst,
    test_user,
    authenticated_client,
    database,
):
    reference = _create_incident(test_user)
    action_id = _create_action(reference, test_user, status="in_progress")
    with authenticated_client.session_transaction() as session:
        session["user_id"] = analyst["id"]
        session["username"] = analyst["username"]
        session["role"] = "admin"
        session["csrf_token"] = "test-csrf-token"

    response = authenticated_client.post(
        f"/incidents/{reference}/actions/{action_id}/status",
        data={
            "status": "completed",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT action_status FROM incident_actions WHERE id = ?",
        (action_id,),
    ).fetchone()["action_status"] == "in_progress"
