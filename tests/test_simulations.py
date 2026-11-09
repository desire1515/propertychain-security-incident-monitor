import sqlite3

import pytest

from database.db import migrate_database_schema
from backend.services.detection_rule_service import get_detection_alerts
from backend.services.simulation_service import (
    SIMULATION_SCENARIOS,
    get_simulation_runs,
    run_simulation,
)


def test_simulation_generates_only_simulated_events_and_records_actor(
    test_user,
    database,
):
    result = run_simulation("unauthorized_role_change", test_user["id"])

    events = database.execute(
        """
        SELECT event_type, classification, source, raw_data
        FROM security_events
        WHERE event_reference = ?
        """,
        (result["event_references"][0],),
    ).fetchone()
    run = database.execute(
        "SELECT * FROM simulation_runs WHERE id = ?",
        (result["id"],),
    ).fetchone()
    audit = database.execute(
        """
        SELECT user_id, action FROM system_audit_logs
        WHERE action = 'SIMULATION_EXECUTED'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()

    assert result["events_generated"] == 1
    assert events["event_type"] == "UNAUTHORIZED_ROLE_CHANGE"
    assert events["classification"] == "SIMULATED"
    assert events["source"].startswith("PCSIRM Simulation /")
    assert str(result["id"]) in events["raw_data"]
    assert run["status"] == "completed"
    assert run["events_generated"] == 1
    assert run["executed_by"] == test_user["id"]
    assert audit["user_id"] == test_user["id"]

    alert = next(
        item for item in get_detection_alerts()
        if item["event_reference"] == result["event_references"][0]
    )
    assert alert["severity"] == "critical"


@pytest.mark.parametrize(
    "scenario_key",
    ["brute_force_login", "repeated_failed_requests"],
)
def test_repeated_simulation_scenarios_trigger_threshold_alerts(
    test_user,
    database,
    scenario_key,
):
    result = run_simulation(scenario_key, test_user["id"])
    references = result["event_references"]

    assert len(references) == 5
    assert database.execute(
        """
        SELECT COUNT(*) FROM security_events
        WHERE event_reference IN (?, ?, ?, ?, ?)
          AND classification = 'SIMULATED'
        """,
        tuple(references),
    ).fetchone()[0] == 5
    assert any(
        alert["event_reference"] == references[-1]
        for alert in get_detection_alerts()
    )


def test_simulations_require_active_administrator(analyst):
    with pytest.raises(ValueError, match="active administrator"):
        run_simulation("brute_force_login", analyst["id"])


def test_invalid_simulation_scenario_is_rejected(test_user):
    with pytest.raises(ValueError, match="Invalid simulation scenario"):
        run_simulation("unknown_scenario", test_user["id"])


def test_simulation_scenario_catalog_covers_requested_cases():
    assert len(SIMULATION_SCENARIOS) == 9


def test_simulation_run_migration_adds_actor_column_without_losing_records(app):
    database_path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(database_path)
    connection.execute("DROP TABLE simulation_runs")
    connection.execute(
        """
        CREATE TABLE simulation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scenario_name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'completed',
            events_generated INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT
        )
        """
    )
    connection.execute(
        """
        INSERT INTO simulation_runs (scenario_name, description, events_generated)
        VALUES ('Legacy run', 'Preserve me', 3)
        """
    )
    connection.commit()
    connection.close()

    migrate_database_schema()
    migrate_database_schema()

    connection = sqlite3.connect(database_path)
    try:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(simulation_runs)")
        }
        row = connection.execute(
            "SELECT scenario_name, description, events_generated, executed_by FROM simulation_runs"
        ).fetchone()
        assert "executed_by" in columns
        assert row == ("Legacy run", "Preserve me", 3, None)
    finally:
        connection.close()


def test_simulation_page_requires_authentication(client):
    assert client.get("/simulations").status_code == 401


def test_analyst_cannot_run_simulation(
    analyst,
    client,
    database,
):
    with client.session_transaction() as session:
        session["user_id"] = analyst["id"]
        session["username"] = analyst["username"]
        session["role"] = analyst["role"]
        session["csrf_token"] = "test-csrf-token"

    before = database.execute(
        "SELECT COUNT(*) FROM simulation_runs"
    ).fetchone()[0]
    response = client.post(
        "/simulations",
        data={
            "scenario": "brute_force_login",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT COUNT(*) FROM simulation_runs"
    ).fetchone()[0] == before


def test_simulation_route_requires_csrf(authenticated_client, database):
    before = database.execute(
        "SELECT COUNT(*) FROM simulation_runs"
    ).fetchone()[0]
    response = authenticated_client.post(
        "/simulations",
        data={"scenario": "brute_force_login"},
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT COUNT(*) FROM simulation_runs"
    ).fetchone()[0] == before
