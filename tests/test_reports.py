import csv
from io import StringIO

from backend.services.detection_rule_service import create_detection_rule
from backend.services.event_service import record_security_event
from backend.services.incident_service import (
    add_incident_action,
    add_incident_evidence,
    create_incident_from_event,
    update_incident_status,
)
from backend.services.monitoring_source_service import create_monitoring_source
from backend.services.report_service import get_report_data
from backend.services.simulation_service import run_simulation


def _event(source, event_type, severity, classification, description):
    return record_security_event(
        source=source,
        event_type=event_type,
        severity=severity,
        classification=classification,
        description=description,
    )


def _login(client, user):
    with client.session_transaction() as session:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]


def test_event_report_aggregates_real_simulated_and_test_records(
    authenticated_client,
):
    _event("Report source one", "REPORT_LOGIN", "high", "REAL", "Real event")
    _event("Report source two", "REPORT_TEST", "low", "TEST", "Test event")
    _event("Report source three", "REPORT_SIM", "medium", "SIMULATED", "Sim event")

    response = authenticated_client.get("/reports?category=events")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Security Events" in body
    assert "REAL events" in body
    assert "SIMULATED events" in body
    assert "TEST events" in body
    assert "Report source one" in body
    assert "Report source two" in body
    assert "Report source three" in body

    data = get_report_data(category="events")["reports"]["events"]
    assert data["total"] == 3
    assert data["by_classification"] == {
        "REAL": 1,
        "SIMULATED": 1,
        "TEST": 1,
    }
    assert data["by_severity"]["high"] == 1


def test_report_date_severity_and_classification_filters_are_applied(
    authenticated_client,
):
    event_reference = _event(
        "Filtered report source",
        "FILTERED_REPORT_EVENT",
        "critical",
        "REAL",
        "Filtered record",
    )
    from database.db import get_db_connection

    with get_db_connection() as connection:
        connection.execute(
            "UPDATE security_events SET received_at = '2024-01-15 12:00:00' "
            "WHERE event_reference = ?",
            (event_reference,),
        )
        connection.commit()

    response = authenticated_client.get(
        "/reports?category=events&start_date=2024-01-01&end_date=2024-01-31"
        "&severity=critical&classification=REAL"
    )
    assert response.status_code == 200
    assert event_reference in response.get_data(as_text=True)
    report = get_report_data(
        category="events",
        start_date="2024-01-01",
        end_date="2024-01-31",
        severity="critical",
        classification="REAL",
    )["reports"]["events"]
    assert report["total"] == 1

    empty = get_report_data(
        category="events",
        start_date="2025-01-01",
        end_date="2025-01-02",
    )["reports"]["events"]
    assert empty["total"] == 0
    assert all(value == 0 for value in empty["by_severity"].values())


def test_incident_report_counts_status_severity_classification_and_dates(
    test_user,
    authenticated_client,
):
    event_reference = _event(
        "Incident report source",
        "INCIDENT_REPORT_EVENT",
        "high",
        "REAL",
        "Incident report test",
    )
    incident_reference = create_incident_from_event(
        event_reference,
        created_by=test_user["id"],
    )
    assert update_incident_status(
        incident_reference,
        "resolved",
        test_user["id"],
    )

    response = authenticated_client.get("/reports?category=incidents")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert incident_reference in body
    assert "Resolved" in body

    report = get_report_data(category="incidents")["reports"]["incidents"]
    incident = next(
        row for row in report["records"]
        if row["incident_reference"] == incident_reference
    )
    assert incident["resolved_at"]
    assert incident["classification"] == "REAL"
    assert report["by_status"]["resolved"] == 1
    filtered = get_report_data(
        category="incidents",
        incident_status="resolved",
        severity="high",
        classification="REAL",
    )["reports"]["incidents"]
    assert filtered["total"] == 1


def test_detection_monitoring_and_simulation_reports_use_database_rows(
    test_user,
    authenticated_client,
):
    create_detection_rule(
        "Report threshold rule",
        "REPORT_THRESHOLD_EVENT",
        "high",
        threshold=1,
        created_by=test_user["id"],
    )
    event_reference = _event(
        "Report detector",
        "REPORT_THRESHOLD_EVENT",
        "high",
        "TEST",
        "Generated a report test alert.",
    )
    create_monitoring_source(
        source_name="Report planned source",
        source_type="APPLICATION",
        description="A reporting fixture source.",
        monitoring_mode="PLANNED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )
    run_simulation("suspicious_admin_login", test_user["id"])

    response = authenticated_client.get("/reports")
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Detection" in body
    assert "Rule execution history" in body
    assert "Monitoring Sources" in body
    assert "Simulations" in body
    assert "Report threshold rule" in body
    assert "Report planned source" in body
    assert "PLANNED" in body
    assert event_reference in body
    assert "Related alerts" in body
    real_filtered = get_report_data(
        category="simulations",
        classification="REAL",
    )["reports"]["simulations"]
    simulated_filtered = get_report_data(
        category="simulations",
        classification="SIMULATED",
    )["reports"]["simulations"]
    assert real_filtered["total"] == 0
    assert simulated_filtered["total"] == 1


def test_report_csv_exports_database_data_and_escapes_spreadsheet_formulas(
    authenticated_client,
):
    description = '=HYPERLINK("https://invalid.example","run")'
    source = 'Source, with "quotes"'
    reference = _event(
        source,
        "CSV_REPORT_EVENT",
        "high",
        "TEST",
        description,
    )
    response = authenticated_client.get("/reports/export.csv?category=events")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    rows = list(csv.reader(StringIO(response.get_data(as_text=True))))
    assert rows[0][0] == "Record type"
    exported = next(row for row in rows[1:] if row[1] == reference)
    assert exported[3] == source
    assert exported[8].startswith("'=")
    assert "HYPERLINK" in exported[8]
    assert response.headers["Content-Disposition"].endswith(
        'filename="pcsirm-events-report.csv"'
    )


def test_csv_exports_cover_incident_detection_monitoring_and_simulations(
    test_user,
    authenticated_client,
):
    event_reference = _event(
        "CSV incident source",
        "CSV_INCIDENT_EVENT",
        "high",
        "REAL",
        "Create an incident report row.",
    )
    incident_reference = create_incident_from_event(
        event_reference,
        created_by=test_user["id"],
    )
    create_detection_rule(
        "CSV detection rule",
        "CSV_DETECTION_EVENT",
        "critical",
        created_by=test_user["id"],
    )
    _event(
        "CSV detection source",
        "CSV_DETECTION_EVENT",
        "critical",
        "TEST",
        "Create a detection report row.",
    )
    create_monitoring_source(
        "CSV monitoring source",
        "APPLICATION",
        monitoring_mode="SIMULATED",
        connection_status="NOT_CONNECTED",
        created_by=test_user["id"],
    )
    run_simulation("suspicious_admin_login", test_user["id"])

    expected_content = {
        "incidents": incident_reference,
        "detection": "CSV detection rule",
        "monitoring": "CSV monitoring source",
        "simulations": "Suspicious administrator login",
    }
    for category, expected in expected_content.items():
        response = authenticated_client.get(
            f"/reports/export.csv?category={category}"
        )
        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        assert expected in response.get_data(as_text=True)
        if category == "detection":
            rows = list(
                csv.reader(StringIO(response.get_data(as_text=True)))
            )
            assert all(len(row) == len(rows[0]) for row in rows)


def test_reports_are_available_to_analysts_and_reject_anonymous_users(
    client,
    analyst,
):
    assert client.get("/reports").status_code == 401
    assert client.get("/reports/export.csv?category=events").status_code == 401
    _login(client, analyst)
    assert client.get("/reports").status_code == 200
    assert client.get("/reports/export.csv?category=incidents").status_code == 200


def test_report_validation_and_empty_category_display(authenticated_client):
    invalid = authenticated_client.get(
        "/reports?start_date=2025-02-01&end_date=2025-01-01"
    )
    assert invalid.status_code == 200
    assert "Start date must not be after end date." in invalid.get_data(
        as_text=True
    )

    empty = authenticated_client.get(
        "/reports?category=events&start_date=2100-01-01&end_date=2100-01-02"
    )
    assert empty.status_code == 200
    assert "No event records match these filters." in empty.get_data(as_text=True)


def test_ingestion_action_evidence_and_audit_reports_use_database_records(
    test_user,
    database,
    authenticated_client,
):
    event_reference = _event(
        "Expanded report source",
        "EXPANDED_REPORT_EVENT",
        "high",
        "REAL",
        "An event for expanded report records.",
    )
    incident_reference = create_incident_from_event(
        event_reference,
        created_by=test_user["id"],
    )
    from backend.services.incident_service import get_incident_by_reference

    incident = get_incident_by_reference(incident_reference)
    action_id = add_incident_action(
        incident["id"],
        "RECOMMENDATION",
        '=HYPERLINK("https://invalid.example","review")',
        performed_by=test_user["id"],
    )
    evidence_id = add_incident_evidence(
        incident["id"],
        evidence_type="REFERENCE",
        description="Retain this evidence reference.",
        evidence_data="https://example.invalid/evidence",
        collected_by=test_user["id"],
    )
    source_id = create_monitoring_source(
        "Expanded report source",
        "APPLICATION",
        created_by=test_user["id"],
    )
    database.execute(
        """
        INSERT INTO monitoring_ingestion_jobs (
            source_id, status, events_seen, events_ingested,
            duplicates_skipped, started_by
        ) VALUES (?, 'completed', 3, 2, 1, ?)
        """,
        (source_id, test_user["id"]),
    )
    database.execute(
        """
        INSERT INTO system_audit_logs (user_id, action, details)
        VALUES (?, 'REPORT_TEST_AUDIT', ?)
        """,
        (
            test_user["id"],
            '=HYPERLINK("https://invalid.example","audit")',
        ),
    )
    database.commit()

    actions = get_report_data(
        category="actions",
        record_status="proposed",
        source="Expanded report source",
        severity="high",
        classification="REAL",
    )["reports"]["actions"]
    assert actions["total"] == 1
    assert actions["records"][0]["id"] == action_id
    assert actions["records"][0]["incident_reference"] == incident_reference

    evidence = get_report_data(
        category="evidence",
        source="Expanded report source",
    )["reports"]["evidence"]
    assert evidence["total"] == 1
    assert evidence["records"][0]["id"] == evidence_id
    assert evidence["custody_entries"] >= 1

    ingestion = get_report_data(
        category="ingestion",
        record_status="completed",
        source="Expanded report source",
    )["reports"]["ingestion"]
    assert ingestion["total"] == 1
    assert ingestion["events_ingested"] == 2
    assert ingestion["duplicates_skipped"] == 1

    audit = get_report_data(
        category="audit",
        record_status="REPORT_TEST_AUDIT",
    )["reports"]["audit"]
    assert audit["total"] == 1

    for category in ("ingestion", "actions", "evidence", "audit"):
        response = authenticated_client.get(
            f"/reports/export.csv?category={category}"
        )
        assert response.status_code == 200
        assert response.mimetype == "text/csv"
        rows = list(csv.reader(StringIO(response.get_data(as_text=True))))
        assert all(
            not value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@"))
            for row in rows
            for value in row
        )

    action_csv = authenticated_client.get(
        "/reports/export.csv?category=actions"
    ).get_data(as_text=True)
    assert "'=HYPERLINK" in action_csv
    audit_csv = authenticated_client.get(
        "/reports/export.csv?category=audit&record_status=REPORT_TEST_AUDIT"
    ).get_data(as_text=True)
    assert "'=HYPERLINK" in audit_csv
