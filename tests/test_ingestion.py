import json

from backend.services.detection_rule_service import (
    create_detection_rule,
    get_detection_alerts,
)
from backend.services.ingestion_service import (
    get_ingestion_jobs,
    ingest_adapter_events,
    run_source_poll,
)
from backend.services.monitoring_source_service import create_monitoring_source


def _activate_verified_source(database, source_id):
    database.execute(
        """
        UPDATE monitoring_sources
        SET monitoring_mode = 'REAL',
            connection_status = 'CONNECTED',
            is_enabled = 1,
            status = 'active',
            last_successful_check = '2026-11-08T00:00:00+00:00'
        WHERE id = ?
        """,
        (source_id,),
    )
    database.commit()


def test_ingestion_deduplicates_external_events_and_evaluates_detection(
    test_user,
    database,
):
    source_id = create_monitoring_source(
        "Trusted test adapter",
        "APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    _activate_verified_source(database, source_id)
    rule_id = create_detection_rule(
        "Ingested event detection",
        "EXTERNAL_ACCESS_DENIED",
        "high",
        threshold=1,
        created_by=test_user["id"],
    )
    events = [
        {
            "external_reference": "provider-event-001",
            "event_type": "EXTERNAL_ACCESS_DENIED",
            "severity": "high",
            "description": "Provider recorded a denied request.",
            "source_timestamp": "2026-11-07T22:15:00+00:00",
            "raw_data": {
                "request_id": "request-1",
                "access_token": "do-not-store-this",
            },
        }
    ]

    first = ingest_adapter_events(source_id, events, started_by=test_user["id"])
    second = ingest_adapter_events(source_id, events, started_by=test_user["id"])

    assert first["status"] == "completed"
    assert first["events_seen"] == 1
    assert first["events_ingested"] == 1
    assert first["duplicates_skipped"] == 0
    assert second["events_ingested"] == 0
    assert second["duplicates_skipped"] == 1
    assert database.execute(
        """
        SELECT COUNT(*) FROM monitoring_ingested_events
        WHERE source_id = ? AND external_reference = ?
        """,
        (source_id, "provider-event-001"),
    ).fetchone()[0] == 1
    event = database.execute(
        """
        SELECT e.* FROM security_events e
        JOIN monitoring_ingested_events m ON m.event_id = e.id
        WHERE m.source_id = ?
        """,
        (source_id,),
    ).fetchone()
    assert event["classification"] == "REAL"
    assert event["source_timestamp"] == "2026-11-07T22:15:00+00:00"
    assert "do-not-store-this" not in event["raw_data"]
    assert json.loads(event["raw_data"])["adapter_metadata"]["access_token"] == (
        "[REDACTED]"
    )
    assert any(
        alert["rule_id"] == rule_id
        and alert["event_reference"] == event["event_reference"]
        for alert in get_detection_alerts()
    )


def test_poll_without_implemented_adapter_records_unavailable_not_success(
    test_user,
    database,
):
    source_id = create_monitoring_source(
        "Planned Firebase source",
        "FIREBASE",
        created_by=test_user["id"],
    )

    job = run_source_poll(source_id, test_user["id"])

    assert job["status"] == "unavailable"
    assert "No verified FIREBASE monitoring adapter" in job["error_summary"]
    assert job["events_ingested"] == 0
    assert get_ingestion_jobs(source_id=source_id)[0]["id"] == job["id"]
    assert database.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0] == 0
    assert database.execute(
        """
        SELECT COUNT(*) FROM system_audit_logs
        WHERE action = 'MONITORING_INGESTION_JOB'
          AND user_id = ?
        """,
        (test_user["id"],),
    ).fetchone()[0] == 1


def test_ingestion_rejects_invalid_batches_without_writing(test_user, database):
    source_id = create_monitoring_source(
        "Invalid batch source",
        "APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    _activate_verified_source(database, source_id)
    before_events = database.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0]
    before_jobs = database.execute(
        "SELECT COUNT(*) FROM monitoring_ingestion_jobs"
    ).fetchone()[0]

    from backend.services.ingestion_service import ingest_adapter_events
    import pytest

    with pytest.raises(ValueError, match="duplicate external references"):
        ingest_adapter_events(
            source_id,
            [
                {
                    "external_reference": "duplicate",
                    "event_type": "ACCESS_DENIED",
                    "severity": "medium",
                    "description": "First.",
                },
                {
                    "external_reference": "duplicate",
                    "event_type": "ACCESS_DENIED",
                    "severity": "medium",
                    "description": "Second.",
                },
            ],
            started_by=test_user["id"],
        )
    assert database.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0] == before_events
    assert database.execute(
        "SELECT COUNT(*) FROM monitoring_ingestion_jobs"
    ).fetchone()[0] == before_jobs


def test_manual_poll_route_requires_admin_and_csrf(
    authenticated_client,
    analyst,
    client,
    test_user,
    database,
):
    source_id = create_monitoring_source(
        "Poll route source",
        "FIREBASE",
        created_by=test_user["id"],
    )
    before = database.execute(
        "SELECT COUNT(*) FROM monitoring_ingestion_jobs"
    ).fetchone()[0]
    response = authenticated_client.post(
        f"/monitoring-sources/{source_id}/poll",
        data={},
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT COUNT(*) FROM monitoring_ingestion_jobs"
    ).fetchone()[0] == before

    with client.session_transaction() as session:
        session["user_id"] = analyst["id"]
        session["username"] = analyst["username"]
        session["role"] = analyst["role"]
        session["csrf_token"] = "test-csrf-token"
    response = client.post(
        f"/monitoring-sources/{source_id}/poll",
        data={"csrf_token": "test-csrf-token"},
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT COUNT(*) FROM monitoring_ingestion_jobs"
    ).fetchone()[0] == before
