import sqlite3

import pytest

from backend.services.incident_service import (
    add_incident_action,
    add_incident_evidence,
    create_incident,
    get_incident_actions,
    get_incident_evidence,
    update_incident_action_status,
)
from database.db import migrate_database_schema


def _create_incident(user_id):
    return create_incident(
        title="Evidence and response workflow test",
        description="A test incident.",
        severity="medium",
        classification="TEST",
        created_by=user_id,
    )


def test_evidence_records_are_append_only_audited_and_redacted(
    test_user,
    database,
):
    from backend.services.incident_service import get_incident_by_reference

    reference = _create_incident(test_user["id"])
    incident_id = get_incident_by_reference(reference)["id"]
    evidence_id = add_incident_evidence(
        incident_id,
        evidence_type="REFERENCE",
        description="Observed token=topSecretValue in a test artifact.",
        evidence_data="https://example.invalid/log?api_key=apiSecretValue",
        collected_by=test_user["id"],
    )

    evidence = get_incident_evidence(incident_id)
    assert len(evidence) == 1
    assert evidence[0]["id"] == evidence_id
    assert evidence[0]["collected_by"] == test_user["id"]
    assert "topSecretValue" not in evidence[0]["description"]
    assert "apiSecretValue" not in evidence[0]["evidence_data"]
    audit = database.execute(
        """
        SELECT user_id, action, details
        FROM system_audit_logs
        WHERE action = 'INCIDENT_EVIDENCE_COLLECTED'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()
    assert audit["user_id"] == test_user["id"]
    assert str(evidence_id) in audit["details"]


@pytest.mark.parametrize(
    ("evidence_type", "description", "actor"),
    [
        ("UNKNOWN", "Valid description", 1),
        ("LOG", "", 1),
        ("LOG", "Valid description", None),
    ],
)
def test_invalid_evidence_data_is_rejected(
    test_user,
    evidence_type,
    description,
    actor,
):
    from backend.services.incident_service import get_incident_by_reference

    reference = _create_incident(test_user["id"])
    incident_id = get_incident_by_reference(reference)["id"]
    with pytest.raises(ValueError):
        add_incident_evidence(
            incident_id,
            evidence_type=evidence_type,
            description=description,
            collected_by=actor,
        )


def test_response_recommendation_lifecycle_is_audited_and_timed(
    test_user,
    database,
):
    from backend.services.incident_service import get_incident_by_reference

    reference = _create_incident(test_user["id"])
    incident_id = get_incident_by_reference(reference)["id"]
    action_id = add_incident_action(
        incident_id,
        action_type="RECOMMENDATION",
        description="Review access logs and rotate affected credentials.",
        performed_by=test_user["id"],
    )

    for status in ("approved", "in_progress", "completed"):
        assert update_incident_action_status(
            action_id,
            status,
            updated_by=test_user["id"],
        ) is True

    action = get_incident_actions(incident_id)[0]
    assert action["id"] == action_id
    assert action["action_status"] == "completed"
    assert action["completed_at"]
    assert action["updated_by"] == test_user["id"]
    assert database.execute(
        """
        SELECT COUNT(*) FROM incident_timeline
        WHERE incident_id = ? AND activity = 'Response recommendation status changed'
        """,
        (incident_id,),
    ).fetchone()[0] == 3
    assert database.execute(
        """
        SELECT COUNT(*) FROM system_audit_logs
        WHERE action = 'INCIDENT_ACTION_STATUS_UPDATED'
        """
    ).fetchone()[0] == 3


def test_response_action_rejects_invalid_transitions_and_types(test_user):
    from backend.services.incident_service import get_incident_by_reference

    reference = _create_incident(test_user["id"])
    incident_id = get_incident_by_reference(reference)["id"]
    with pytest.raises(ValueError, match="recommendations or controlled simulations"):
        add_incident_action(
            incident_id,
            action_type="EXECUTE_CONTAINMENT",
            description="This must not run.",
            performed_by=test_user["id"],
        )
    action_id = add_incident_action(
        incident_id,
        action_type="SIMULATION",
        description="Record a controlled simulation recommendation.",
        performed_by=test_user["id"],
    )
    with pytest.raises(ValueError, match="cannot transition"):
        update_incident_action_status(
            action_id,
            "completed",
            updated_by=test_user["id"],
        )


def test_incident_detail_route_records_evidence_and_recommendations(
    authenticated_client,
    test_user,
):
    reference = _create_incident(test_user["id"])
    response = authenticated_client.get(f"/incidents/{reference}")
    assert "Evidence Register" in response.get_data(as_text=True)
    assert "Response Recommendations" in response.get_data(as_text=True)

    response = authenticated_client.post(
        f"/incidents/{reference}/evidence",
        data={
            "evidence_type": "LOG",
            "description": "Relevant test log excerpt.",
            "evidence_data": "log://test/entry-1",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Evidence record added" in response.get_data(as_text=True)

    response = authenticated_client.post(
        f"/incidents/{reference}/actions",
        data={
            "action_type": "RECOMMENDATION",
            "description": "Recommend review by the authorized administrator.",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "PCSIRM did not execute it" in response.get_data(as_text=True)


def test_evidence_route_rejects_missing_csrf_without_writing(
    authenticated_client,
    test_user,
    database,
):
    reference = _create_incident(test_user["id"])
    before = database.execute(
        "SELECT COUNT(*) FROM incident_evidence"
    ).fetchone()[0]

    response = authenticated_client.post(
        f"/incidents/{reference}/evidence",
        data={
            "evidence_type": "LOG",
            "description": "Should not be recorded.",
        },
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT COUNT(*) FROM incident_evidence"
    ).fetchone()[0] == before


def test_incident_evidence_migration_preserves_existing_record(app):
    path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DROP TABLE incident_evidence")
    connection.execute(
        """
        CREATE TABLE incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,
            description TEXT,
            evidence_data TEXT,
            collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        INSERT INTO incident_evidence (
            incident_id, evidence_type, description, evidence_data
        )
        VALUES (1, 'LOG', 'Legacy evidence', 'legacy://reference')
        """
    )
    connection.commit()
    connection.close()

    migrate_database_schema()
    migrate_database_schema()

    connection = sqlite3.connect(path)
    try:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(incident_evidence)")
        }
        row = connection.execute(
            "SELECT evidence_type, description, evidence_data, collected_by FROM incident_evidence"
        ).fetchone()
        assert "collected_by" in columns
        assert row == ("LOG", "Legacy evidence", "legacy://reference", None)
    finally:
        connection.close()
