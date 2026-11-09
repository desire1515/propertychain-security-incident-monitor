import sqlite3

import pytest

from backend.services.detection_rule_service import (
    DEFAULT_DETECTION_RULES,
    create_detection_rule,
    ensure_default_detection_rules,
    get_detection_alerts,
    get_detection_alert_history,
    get_detection_rule_by_id,
    get_detection_rules,
    set_detection_alert_status,
    set_detection_rule_enabled,
    update_detection_rule,
)
from backend.services.auth_service import authenticate_user
from backend.services.incident_service import create_incident_from_event
from backend.services.event_service import record_security_event
from database.db import migrate_database_schema


def _record_event(event_type="ACCESS_DENIED", source="Test Adapter"):
    return record_security_event(
        source=source,
        event_type=event_type,
        severity="medium",
        classification="TEST",
        description="A controlled detection-rule test event.",
    )


def test_default_detection_rules_are_created_idempotently():
    ensure_default_detection_rules()
    ensure_default_detection_rules()

    rules = get_detection_rules()
    default_names = {item[0] for item in DEFAULT_DETECTION_RULES}
    assert default_names <= {rule["rule_name"] for rule in rules}
    assert sum(rule["rule_name"] in default_names for rule in rules) == len(
        default_names
    )


def test_detection_rule_migration_adds_threshold_fields_and_is_repeatable(app):
    database_path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DROP TABLE detection_alerts")
    connection.execute("DROP TABLE detection_rule_executions")
    connection.execute("DROP TABLE detection_rules")
    connection.execute(
        """
        CREATE TABLE detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            description TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        INSERT INTO detection_rules (rule_name, description, event_type, severity)
        VALUES ('Legacy rule', 'Existing description', 'LEGACY_EVENT', 'high')
        """
    )
    connection.commit()
    connection.close()

    migrate_database_schema()
    migrate_database_schema()

    migrated = sqlite3.connect(database_path)
    try:
        migrated.row_factory = sqlite3.Row
        columns = {
            row["name"]
            for row in migrated.execute("PRAGMA table_info(detection_rules)")
        }
        assert {"threshold", "window_minutes", "created_by", "updated_at"} <= columns
        legacy = migrated.execute(
            "SELECT * FROM detection_rules WHERE rule_name = 'Legacy rule'"
        ).fetchone()
        assert legacy["event_type"] == "LEGACY_EVENT"
        assert legacy["threshold"] == 1
        assert legacy["window_minutes"] == 60
        assert legacy["updated_at"]
        assert migrated.execute(
            "SELECT COUNT(*) FROM detection_rules WHERE rule_name = 'Legacy rule'"
        ).fetchone()[0] == 1
        assert migrated.execute(
            "SELECT COUNT(*) FROM detection_alerts"
        ).fetchone()[0] == 0
    finally:
        migrated.close()


def test_threshold_rule_creates_alert_linked_to_triggering_event(
    test_user,
    database,
):
    rule_id = create_detection_rule(
        rule_name="Two access denials",
        event_type="ACCESS_DENIED",
        severity="high",
        threshold=2,
        window_minutes=60,
        created_by=test_user["id"],
    )
    _record_event()
    second_reference = _record_event()

    alerts = get_detection_alerts(status="open")
    alert = next(item for item in alerts if item["rule_id"] == rule_id)
    assert alert["event_reference"] == second_reference
    assert alert["severity"] == "high"
    assert alert["status"] == "open"

    executions = database.execute(
        """
        SELECT matched, matching_count
        FROM detection_rule_executions
        WHERE rule_id = ?
        ORDER BY id
        """,
        (rule_id,),
    ).fetchall()
    assert [(row["matched"], row["matching_count"]) for row in executions] == [
        (0, 1),
        (1, 2),
    ]


def test_repeated_failed_logins_generate_an_authentication_alert(test_user):
    for _ in range(5):
        assert authenticate_user(
            test_user["username"],
            "incorrect-login-password",
        ) is None

    alerts = get_detection_alerts(status="open")
    auth_alerts = [
        alert for alert in alerts
        if alert["rule_name"] == "Repeated failed login attempts"
    ]
    assert len(auth_alerts) == 1
    assert auth_alerts[0]["classification"] == "TEST"


def test_open_alert_is_not_duplicated_for_same_rule_and_source(
    test_user,
    database,
):
    rule_id = create_detection_rule(
        rule_name="Repeated source activity",
        event_type="ACCESS_DENIED",
        severity="medium",
        threshold=2,
        window_minutes=30,
        created_by=test_user["id"],
    )
    for _ in range(3):
        _record_event()

    assert len(
        [alert for alert in get_detection_alerts() if alert["rule_id"] == rule_id]
    ) == 1
    assert database.execute(
        "SELECT COUNT(*) FROM detection_rule_executions WHERE rule_id = ?",
        (rule_id,),
    ).fetchone()[0] == 3


def test_rule_edit_updates_configuration_and_skips_unchanged_audit(
    test_user,
    database,
):
    rule_id = create_detection_rule(
        rule_name="Editable rule",
        event_type="ACCESS_DENIED",
        severity="medium",
        threshold=1,
        window_minutes=60,
        created_by=test_user["id"],
    )
    assert update_detection_rule(
        rule_id,
        rule_name="Updated rule",
        event_type="ACCESS_DENIED",
        severity="high",
        threshold=3,
        window_minutes=15,
        description="Updated description",
        updated_by=test_user["id"],
    ) is True
    before = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'DETECTION_RULE_UPDATED'"
    ).fetchone()[0]

    assert update_detection_rule(
        rule_id,
        rule_name="Updated rule",
        event_type="ACCESS_DENIED",
        severity="high",
        threshold=3,
        window_minutes=15,
        description="Updated description",
        updated_by=test_user["id"],
    ) is False
    rule = get_detection_rule_by_id(rule_id)
    assert rule["threshold"] == 3
    assert rule["window_minutes"] == 15
    assert rule["severity"] == "high"
    assert database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'DETECTION_RULE_UPDATED'"
    ).fetchone()[0] == before


def test_resolving_alert_allows_a_later_alert_for_same_rule_and_source(
    test_user,
):
    rule_id = create_detection_rule(
        rule_name="Resolvable source activity",
        event_type="ACCESS_DENIED",
        severity="medium",
        threshold=2,
        window_minutes=60,
        created_by=test_user["id"],
    )
    _record_event()
    _record_event()
    alert = next(
        item for item in get_detection_alerts() if item["rule_id"] == rule_id
    )

    assert set_detection_alert_status(
        alert["id"],
        "resolved",
        updated_by=test_user["id"],
    ) is True
    _record_event()

    alerts = [
        item for item in get_detection_alerts() if item["rule_id"] == rule_id
    ]
    assert len(alerts) == 2
    assert {item["status"] for item in alerts} == {"open", "resolved"}


def test_alert_is_linked_to_incident_from_triggering_event(test_user):
    create_detection_rule(
        rule_name="Link alert to incident",
        event_type="LINKABLE_EVENT",
        severity="high",
        created_by=test_user["id"],
    )
    event_reference = _record_event(event_type="LINKABLE_EVENT")
    incident_reference = create_incident_from_event(
        event_reference,
        created_by=test_user["id"],
    )

    alert = next(
        item
        for item in get_detection_alerts()
        if item["event_reference"] == event_reference
    )
    assert alert["incident_reference"] == incident_reference


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_name", ""),
        ("event_type", "not a valid event type"),
        ("severity", "urgent"),
        ("threshold", 0),
        ("window_minutes", 10081),
    ],
)
def test_invalid_detection_rule_settings_are_rejected(test_user, field, value):
    values = {
        "rule_name": "Invalid test rule",
        "event_type": "TEST_EVENT",
        "severity": "medium",
        "threshold": 1,
        "window_minutes": 60,
        "created_by": test_user["id"],
    }
    values[field] = value
    with pytest.raises(ValueError):
        create_detection_rule(**values)


def test_only_administrators_can_manage_rules(analyst, test_user):
    with pytest.raises(ValueError, match="active administrator"):
        create_detection_rule(
            rule_name="Analyst-created rule",
            event_type="TEST_EVENT",
            severity="medium",
            created_by=analyst["id"],
        )

    rule_id = create_detection_rule(
        rule_name="Administrator rule",
        event_type="TEST_EVENT",
        severity="medium",
        created_by=test_user["id"],
    )
    with pytest.raises(ValueError, match="active administrator"):
        set_detection_rule_enabled(rule_id, False, updated_by=analyst["id"])


def test_unchanged_rule_state_creates_no_audit_record(test_user, database):
    rule_id = create_detection_rule(
        rule_name="Unchanged rule state",
        event_type="TEST_EVENT",
        severity="low",
        created_by=test_user["id"],
    )
    before = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'DETECTION_RULE_ENABLED'"
    ).fetchone()[0]

    assert set_detection_rule_enabled(
        rule_id,
        True,
        updated_by=test_user["id"],
    ) is False
    after = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'DETECTION_RULE_ENABLED'"
    ).fetchone()[0]
    assert after == before


def test_detection_alert_acknowledgement_and_investigation_history(
    test_user,
    database,
):
    rule_id = create_detection_rule(
        rule_name="Alert lifecycle rule",
        event_type="ALERT_LIFECYCLE_EVENT",
        severity="high",
        created_by=test_user["id"],
    )
    event_reference = _record_event("ALERT_LIFECYCLE_EVENT")
    alert = next(
        item
        for item in get_detection_alerts()
        if item["rule_id"] == rule_id
    )

    for next_status in ("acknowledged", "investigating", "resolved"):
        assert set_detection_alert_status(
            alert["id"],
            next_status,
            test_user["id"],
        )

    history = get_detection_alert_history(alert["id"])
    assert [
        (item["previous_status"], item["new_status"], item["changed_by"])
        for item in history
    ] == [
        (None, "open", None),
        ("open", "acknowledged", test_user["id"]),
        ("acknowledged", "investigating", test_user["id"]),
        ("investigating", "resolved", test_user["id"]),
    ]
    assert history[0]["changed_at"]
    assert history[1]["changed_by_username"] == test_user["username"]
    assert database.execute(
        """
        SELECT COUNT(*) FROM system_audit_logs
        WHERE action = 'DETECTION_ALERT_STATUS_CHANGED'
        """
    ).fetchone()[0] == 3


def test_alert_invalid_transition_does_not_change_status_or_history(
    test_user,
    database,
):
    rule_id = create_detection_rule(
        rule_name="Alert transition guard",
        event_type="ALERT_TRANSITION_EVENT",
        severity="medium",
        created_by=test_user["id"],
    )
    _record_event("ALERT_TRANSITION_EVENT")
    alert = next(
        item for item in get_detection_alerts() if item["rule_id"] == rule_id
    )
    history_before = len(get_detection_alert_history(alert["id"]))
    audit_before = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs "
        "WHERE action = 'DETECTION_ALERT_STATUS_CHANGED'"
    ).fetchone()[0]

    with pytest.raises(ValueError, match="cannot transition"):
        set_detection_alert_status(alert["id"], "investigating", test_user["id"])

    refreshed = next(
        item
        for item in get_detection_alerts()
        if item["id"] == alert["id"]
    )
    assert refreshed["status"] == "open"
    assert len(get_detection_alert_history(alert["id"])) == history_before
    assert database.execute(
        "SELECT COUNT(*) FROM system_audit_logs "
        "WHERE action = 'DETECTION_ALERT_STATUS_CHANGED'"
    ).fetchone()[0] == audit_before


def test_detection_rule_pages_require_authentication(client):
    assert client.get("/detection-rules").status_code == 401
    assert client.get("/detection-alerts").status_code == 401


def test_analyst_cannot_create_rule_from_route(analyst, client):
    with client.session_transaction() as session:
        session["user_id"] = analyst["id"]
        session["username"] = analyst["username"]
        session["role"] = analyst["role"]
        session["csrf_token"] = "test-csrf-token"

    response = client.post(
        "/detection-rules",
        data={
            "rule_name": "Route analyst rule",
            "event_type": "TEST_EVENT",
            "severity": "medium",
            "threshold": "1",
            "window_minutes": "60",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    assert all(
        rule["rule_name"] != "Route analyst rule"
        for rule in get_detection_rules()
    )


def test_detection_rule_route_requires_csrf(authenticated_client):
    response = authenticated_client.post(
        "/detection-rules",
        data={
            "rule_name": "CSRF protected rule",
            "event_type": "TEST_EVENT",
            "severity": "medium",
            "threshold": "1",
            "window_minutes": "60",
        },
    )
    assert response.status_code == 302
    assert all(
        rule["rule_name"] != "CSRF protected rule"
        for rule in get_detection_rules()
    )


def test_administrator_can_create_and_edit_rule_through_pages(
    authenticated_client,
):
    response = authenticated_client.post(
        "/detection-rules",
        data={
            "rule_name": "Route managed rule",
            "event_type": "ROUTE_EVENT",
            "severity": "medium",
            "threshold": "2",
            "window_minutes": "15",
            "description": "Original description",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    rule = next(
        item for item in get_detection_rules()
        if item["rule_name"] == "Route managed rule"
    )

    response = authenticated_client.post(
        f"/detection-rules/{rule['id']}/edit",
        data={
            "rule_name": "Route managed rule",
            "event_type": "ROUTE_EVENT",
            "severity": "high",
            "threshold": "3",
            "window_minutes": "30",
            "description": "Updated description",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    updated = next(
        item for item in get_detection_rules()
        if item["id"] == rule["id"]
    )
    assert updated["severity"] == "high"
    assert updated["threshold"] == 3
    assert updated["window_minutes"] == 30
