import sqlite3
import warnings

import pytest

from backend.services.auth_service import create_user
from backend.services.monitoring_source_service import (
    ALLOWED_CONNECTION_STATUSES,
    ALLOWED_MONITORING_MODES,
    ALLOWED_SOURCE_TYPES,
    create_monitoring_source,
    ensure_default_monitoring_sources,
    get_monitoring_source_by_id,
    get_monitoring_sources,
    record_monitoring_check,
    update_monitoring_source,
    update_monitoring_source_status,
)
from database.db import get_db_connection, migrate_database_schema


@pytest.fixture
def admin_session(client, test_user):
    with client.session_transaction() as session:
        session["user_id"] = test_user["id"]
        session["username"] = test_user["username"]
        session["role"] = test_user["role"]
        session["csrf_token"] = "test-csrf-token"
    return client


def test_valid_monitoring_source_registration(test_user, database):
    source_id = create_monitoring_source(
        source_name="Test Source A",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )

    source = get_monitoring_source_by_id(source_id)
    assert source["source_name"] == "Test Source A"
    assert source["source_type"] == "APPLICATION"
    assert source["monitoring_mode"] == "SIMULATED"
    assert source["connection_status"] == "NOT_CONNECTED"
    assert source["is_enabled"] == 0


def test_missing_source_name_raises_value_error(test_user):
    with pytest.raises(ValueError, match="Source name is required"):
        create_monitoring_source(
            source_name="   ",
            source_type="APPLICATION",
            created_by=test_user["id"],
        )


def test_invalid_source_type_raises_value_error(test_user):
    with pytest.raises(ValueError, match="Invalid source type"):
        create_monitoring_source(
            source_name="Bad Source",
            source_type="NOT_A_TYPE",
            created_by=test_user["id"],
        )


def test_invalid_monitoring_mode_raises_value_error(test_user):
    with pytest.raises(ValueError, match="Invalid monitoring mode"):
        create_monitoring_source(
            source_name="Bad Mode Source",
            source_type="APPLICATION",
            monitoring_mode="INVALID",
            created_by=test_user["id"],
        )


def test_invalid_connection_status_raises_value_error(test_user):
    with pytest.raises(ValueError, match="Invalid connection status"):
        create_monitoring_source(
            source_name="Bad Status Source",
            source_type="APPLICATION",
            connection_status="INVALID",
            created_by=test_user["id"],
        )


def test_duplicate_source_name_is_rejected(test_user):
    create_monitoring_source(
        source_name="Duplicate Source",
        source_type="APPLICATION",
        created_by=test_user["id"],
    )

    with pytest.raises(ValueError, match="already exists"):
        create_monitoring_source(
            source_name="duplicate source",
            source_type="SIMULATION",
            created_by=test_user["id"],
        )


def test_planned_source_cannot_be_connected(test_user):
    with pytest.raises(ValueError, match="must not be marked CONNECTED"):
        create_monitoring_source(
            source_name="Planned Source",
            source_type="FIREBASE",
            monitoring_mode="PLANNED",
            connection_status="CONNECTED",
            is_enabled=True,
            created_by=test_user["id"],
        )


def test_disabled_source_cannot_be_connected(test_user):
    with pytest.raises(ValueError, match="Disabled sources must not be reported as actively connected"):
        create_monitoring_source(
            source_name="Disabled Source",
            source_type="APPLICATION",
            connection_status="CONNECTED",
            is_enabled=False,
            created_by=test_user["id"],
        )


def test_valid_update_and_invalid_update(test_user):
    source_id = create_monitoring_source(
        source_name="Editable Source",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        description="Initial",
        created_by=test_user["id"],
    )

    assert update_monitoring_source(
        source_id,
        source_name="Updated Source",
        source_type="SIMULATION",
        description="Updated description",
        monitoring_mode="SIMULATED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        updated_by=test_user["id"],
    ) is True

    with pytest.raises(ValueError, match="Invalid monitoring source ID"):
        update_monitoring_source(999999, source_name="Bad", updated_by=test_user["id"])


def test_unchanged_update_creates_no_audit_entry(test_user, database):
    source_id = create_monitoring_source(
        source_name="Stable Source",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        created_by=test_user["id"],
    )

    before_count = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'MONITORING_SOURCE_UPDATED'"
    ).fetchone()[0]

    result = update_monitoring_source(
        source_id,
        source_name="Stable Source",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        updated_by=test_user["id"],
    )

    after_count = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs WHERE action = 'MONITORING_SOURCE_UPDATED'"
    ).fetchone()[0]

    assert result is False
    assert after_count == before_count


def test_monitoring_pages_require_authentication(client):
    for path in [
        "/monitoring-sources",
        "/monitoring-sources/new",
        "/monitoring-sources/1",
    ]:
        response = client.get(path)
        assert response.status_code == 401


def test_analysts_cannot_administer_monitoring_sources(analyst, client):
    with client.session_transaction() as session:
        session["user_id"] = analyst["id"]
        session["username"] = analyst["username"]
        session["role"] = analyst["role"]
        session["csrf_token"] = "test-csrf-token"

    response = client.post(
        "/monitoring-sources/new",
        data={
            "source_name": "Analyst Attempt",
            "source_type": "APPLICATION",
            "monitoring_mode": "SIMULATED",
            "connection_status": "NOT_CONNECTED",
            "is_enabled": "",
            "csrf_token": "test-csrf-token",
        },
    )
    assert response.status_code == 302


def test_analysts_cannot_change_status_check_or_initialize_sources(
    analyst,
    client,
    test_user,
    database,
):
    source_id = create_monitoring_source(
        source_name="Admin Only Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    with client.session_transaction() as session:
        session["user_id"] = analyst["id"]
        session["username"] = analyst["username"]
        session["role"] = analyst["role"]
        session["csrf_token"] = "test-csrf-token"

    before_audit_count = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs"
    ).fetchone()[0]
    for path, data in (
        (f"/monitoring-sources/{source_id}/status", {"status": "CONNECTED"}),
        (f"/monitoring-sources/{source_id}/check", {"result": "success"}),
        ("/monitoring-sources/setup", {}),
    ):
        response = client.post(
            path,
            data={**data, "csrf_token": "test-csrf-token"},
        )
        assert response.status_code == 302

    source = get_monitoring_source_by_id(source_id)
    assert source["connection_status"] == "NOT_CONNECTED"
    assert source["is_enabled"] == 0
    assert database.execute(
        "SELECT COUNT(*) FROM system_audit_logs"
    ).fetchone()[0] == before_audit_count


@pytest.mark.parametrize(
    ("path_suffix", "data"),
    [
        ("/status", {"status": "DISABLED"}),
        ("/check", {"result": "success"}),
    ],
)
@pytest.mark.parametrize("csrf_token", [None, "invalid-csrf-token"])
def test_admin_state_changing_routes_require_valid_csrf(
    admin_session,
    test_user,
    database,
    path_suffix,
    data,
    csrf_token,
):
    source_id = create_monitoring_source(
        source_name=f"CSRF Source {path_suffix} {csrf_token}",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    before_audit_count = database.execute(
        "SELECT COUNT(*) FROM system_audit_logs"
    ).fetchone()[0]

    form_data = dict(data)
    if csrf_token is not None:
        form_data["csrf_token"] = csrf_token
    response = admin_session.post(
        f"/monitoring-sources/{source_id}{path_suffix}",
        data=form_data,
    )

    assert response.status_code == 302
    source = get_monitoring_source_by_id(source_id)
    assert source["connection_status"] == "NOT_CONNECTED"
    assert source["is_enabled"] == 0
    assert database.execute(
        "SELECT COUNT(*) FROM system_audit_logs"
    ).fetchone()[0] == before_audit_count


def test_admin_can_register_source_in_route(admin_session):
    response = admin_session.post(
        "/monitoring-sources/new",
        data={
            "source_name": "Route Source",
            "source_type": "APPLICATION",
            "monitoring_mode": "SIMULATED",
            "connection_status": "NOT_CONNECTED",
            "is_enabled": "",
            "csrf_token": "test-csrf-token",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    source = get_monitoring_sources(search_query="Route Source")
    assert source and source[0]["source_name"] == "Route Source"


def test_manual_success_does_not_establish_true_connection(test_user, database):
    source_id = create_monitoring_source(
        source_name="Manual Source",
        source_type="FIREBASE",
        monitoring_mode="PLANNED",
        connection_status="NOT_CONNECTED",
        created_by=test_user["id"],
    )

    updated = record_monitoring_check(
        source_id,
        success=True,
        checked_by=test_user["id"],
    )
    assert updated["connection_status"] == "NOT_CONNECTED"
    assert updated["last_successful_check"] is None


def test_manual_success_preserves_genuine_connected_state(test_user, database):
    source_id = create_monitoring_source(
        source_name="Verified Connected Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    successful_check = "2026-11-05T12:00:00+00:00"
    database.execute(
        """
        UPDATE monitoring_sources
        SET connection_status = 'CONNECTED',
            is_enabled = 1,
            status = 'active',
            last_successful_check = ?,
            last_error = 'Previous integration warning'
        WHERE id = ?
        """,
        (successful_check, source_id),
    )
    database.commit()

    updated = record_monitoring_check(
        source_id,
        success=True,
        checked_by=test_user["id"],
    )

    assert updated["connection_status"] == "CONNECTED"
    assert updated["is_enabled"] == 1
    assert updated["last_successful_check"] == successful_check
    assert updated["last_error"] == "Previous integration warning"


def test_manual_failure_preserves_genuine_connected_state(test_user, database):
    source_id = create_monitoring_source(
        source_name="Connected Failure Check Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    successful_check = "2026-11-05T12:00:00+00:00"
    database.execute(
        """
        UPDATE monitoring_sources
        SET connection_status = 'CONNECTED',
            is_enabled = 1,
            status = 'active',
            last_successful_check = ?
        WHERE id = ?
        """,
        (successful_check, source_id),
    )
    database.commit()

    updated = record_monitoring_check(
        source_id,
        success=False,
        error="manual observation only",
        checked_by=test_user["id"],
    )

    assert updated["connection_status"] == "CONNECTED"
    assert updated["is_enabled"] == 1
    assert updated["last_successful_check"] == successful_check
    assert updated["last_error"] == "manual observation only"


def test_caller_cannot_supply_verified_true_to_manual_check(test_user):
    source_id = create_monitoring_source(
        source_name="No Caller Verification Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )

    with pytest.raises(TypeError, match="verified"):
        record_monitoring_check(
            source_id,
            success=True,
            checked_by=test_user["id"],
            verified=True,
        )

    source = get_monitoring_source_by_id(source_id)
    assert source["connection_status"] == "NOT_CONNECTED"
    assert source["last_successful_check"] is None


def test_failed_check_preserves_success_timestamp(test_user, database):
    source_id = create_monitoring_source(
        source_name="Real Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )
    database.execute(
        "UPDATE monitoring_sources SET last_successful_check = ?, last_checked_at = ? WHERE id = ?",
        ("2024-01-01T00:00:00+00:00", "2024-01-01T00:00:00+00:00", source_id),
    )
    database.commit()

    record_monitoring_check(
        source_id,
        success=False,
        error="secret token abc123",
        checked_by=test_user["id"],
    )
    source = get_monitoring_source_by_id(source_id)

    assert source["last_successful_check"] == "2024-01-01T00:00:00+00:00"
    audit = database.execute(
        "SELECT details FROM system_audit_logs WHERE action = 'MONITORING_SOURCE_CHECKED' ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]
    assert "abc123" not in audit.lower()
    assert "token" not in audit.lower()


def test_failed_check_keeps_disabled_source_disabled(test_user):
    source_id = create_monitoring_source(
        source_name="Disabled Manual Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        connection_status="DISABLED",
        is_enabled=False,
        created_by=test_user["id"],
    )

    updated = record_monitoring_check(
        source_id,
        success=False,
        error="error occurred",
        checked_by=test_user["id"],
    )
    assert updated["connection_status"] == "DISABLED"
    assert updated["is_enabled"] == 0


def test_planned_source_stays_not_connected_after_check(test_user):
    source_id = create_monitoring_source(
        source_name="Planned Check Source",
        source_type="FIREBASE",
        monitoring_mode="PLANNED",
        created_by=test_user["id"],
    )

    updated = record_monitoring_check(
        source_id,
        success=True,
        checked_by=test_user["id"],
    )
    assert updated["monitoring_mode"] == "PLANNED"
    assert updated["connection_status"] == "NOT_CONNECTED"
    assert updated["last_successful_check"] is None


def test_default_monitoring_sources_are_created_once(test_user):
    ensure_default_monitoring_sources()
    ensure_default_monitoring_sources()

    sources = get_monitoring_sources()
    names = {source["source_name"] for source in sources}
    expected = {
        "PropertyChain Firebase",
        "Ethereum Sepolia Smart Contracts",
        "PCSIRM Application",
        "PCSIRM Simulation Engine",
    }
    assert names >= expected
    assert len([item for item in sources if item["source_name"] in expected]) == 4


def test_default_initialization_preserves_existing_settings(test_user):
    source_id = create_monitoring_source(
        source_name="PropertyChain Firebase",
        source_type="FIREBASE",
        monitoring_mode="PLANNED",
        description="Original text",
        created_by=test_user["id"],
    )

    ensure_default_monitoring_sources()
    source = get_monitoring_source_by_id(source_id)
    assert source["description"] == "Original text"
    assert source["monitoring_mode"] == "PLANNED"


def test_get_monitoring_sources_supports_filters_and_search(test_user):
    create_monitoring_source(
        source_name="Filter By Type",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )
    create_monitoring_source(
        source_name="Filter By Blockchain",
        source_type="BLOCKCHAIN",
        monitoring_mode="PLANNED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )

    assert get_monitoring_sources(source_type="APPLICATION")
    assert get_monitoring_sources(monitoring_mode="PLANNED")
    assert get_monitoring_sources(connection_status="NOT_CONNECTED")
    assert get_monitoring_sources(is_enabled=False)
    assert any(item["source_name"] == "Filter By Type" for item in get_monitoring_sources(search_query="Type"))


def test_monitoring_source_detail_display_data(admin_session, test_user):
    source_id = create_monitoring_source(
        source_name="Detail Source",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        description="Visible description",
        created_by=test_user["id"],
    )

    response = admin_session.get(f"/monitoring-sources/{source_id}")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Detail Source" in body
    assert "Visible description" in body


def test_database_migration_adds_missing_columns_and_preserves_rows(app):
    path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE IF EXISTS monitoring_sources")
    connection.execute(
        """
        CREATE TABLE monitoring_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'inactive',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "INSERT INTO monitoring_sources (source_name, source_type, status) VALUES (?, ?, ?)",
        ("Legacy Source", "APPLICATION", "inactive"),
    )
    connection.commit()
    connection.close()

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        migrate_database_schema()
    assert not caught

    with get_db_connection() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(monitoring_sources)").fetchall()}
        assert {"description", "monitoring_mode", "connection_status", "is_enabled", "last_successful_check", "updated_at"}.issubset(columns)
        row = conn.execute("SELECT source_name, source_type FROM monitoring_sources WHERE source_name = ?", ("Legacy Source",)).fetchone()
        assert row is not None
        assert row["source_type"] == "APPLICATION"


def test_unverified_real_source_cannot_become_connected(test_user):
    source_id = create_monitoring_source(
        source_name="Unverified Real Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )

    with pytest.raises(ValueError, match="successful verified integration check"):
        update_monitoring_source(
            source_id,
            connection_status="CONNECTED",
            is_enabled=True,
            updated_by=test_user["id"],
        )


def test_unverified_real_source_cannot_become_degraded(test_user):
    source_id = create_monitoring_source(
        source_name="Unverified Degraded Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )

    with pytest.raises(ValueError, match="successful verified integration check"):
        update_monitoring_source(
            source_id,
            connection_status="DEGRADED",
            is_enabled=True,
            updated_by=test_user["id"],
        )


@pytest.mark.parametrize("requested_status", ["ACTIVE", "CONNECTED", "DEGRADED"])
def test_unverified_real_source_cannot_be_activated_by_status_route(
    test_user,
    requested_status,
):
    source_id = create_monitoring_source(
        source_name=f"Unverified Status Source {requested_status}",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    if requested_status == "DEGRADED":
        with get_db_connection() as connection:
            connection.execute(
                """
                UPDATE monitoring_sources
                SET connection_status = 'ERROR', is_enabled = 1
                WHERE id = ?
                """,
                (source_id,),
            )
            connection.commit()

    before = get_monitoring_source_by_id(source_id)
    with pytest.raises(ValueError, match="successful verified integration check"):
        update_monitoring_source_status(
            source_id,
            requested_status,
            updated_by=test_user["id"],
        )

    source = get_monitoring_source_by_id(source_id)
    assert source["connection_status"] == before["connection_status"]
    assert source["is_enabled"] == before["is_enabled"]


def test_verified_real_source_status_update_reads_sqlite_row(test_user, database):
    source_id = create_monitoring_source(
        source_name="Previously Verified Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    database.execute(
        "UPDATE monitoring_sources SET last_successful_check = ? WHERE id = ?",
        ("2026-11-05T12:00:00+00:00", source_id),
    )
    database.commit()

    assert update_monitoring_source_status(
        source_id,
        "CONNECTED",
        updated_by=test_user["id"],
    ) is True
    source = get_monitoring_source_by_id(source_id)
    assert source["connection_status"] == "CONNECTED"
    assert source["is_enabled"] == 1


def test_manual_check_records_actor_id(test_user):
    source_id = create_monitoring_source(
        source_name="Checked Source",
        source_type="APPLICATION",
        monitoring_mode="SIMULATED",
        connection_status="NOT_CONNECTED",
        is_enabled=False,
        created_by=test_user["id"],
    )

    record_monitoring_check(
        source_id,
        success=False,
        error="secret token abc123",
        checked_by=test_user["id"],
    )

    with get_db_connection() as conn:
        audit = conn.execute(
            "SELECT user_id, details FROM system_audit_logs WHERE action = 'MONITORING_SOURCE_CHECKED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert audit["user_id"] == test_user["id"]
    assert "abc123" not in (audit["details"] or "").lower()


def test_manual_check_sanitizes_credentials_in_last_error_and_audit(
    test_user,
    database,
):
    source_id = create_monitoring_source(
        source_name="Sanitized Error Source",
        source_type="APPLICATION",
        monitoring_mode="REAL",
        created_by=test_user["id"],
    )
    sensitive_values = (
        "tokSecret987",
        "secSecret987",
        "passSecret987",
        "apiSecret987",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signatureValue",
    )
    error = (
        "token=tokSecret987 secret=secSecret987 password=passSecret987 "
        "api_key=apiSecret987 "
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signatureValue"
    )

    record_monitoring_check(
        source_id,
        success=False,
        error=error,
        checked_by=test_user["id"],
    )
    source = get_monitoring_source_by_id(source_id)
    audit = database.execute(
        """
        SELECT user_id, details FROM system_audit_logs
        WHERE action = 'MONITORING_SOURCE_CHECKED'
        ORDER BY id DESC LIMIT 1
        """
    ).fetchone()

    assert audit["user_id"] == test_user["id"]
    for sensitive_value in sensitive_values:
        assert sensitive_value.lower() not in source["last_error"].lower()
        assert sensitive_value.lower() not in audit["details"].lower()


def test_migration_handles_duplicate_names_safely(app):
    path = app.config["DATABASE_PATH"]
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE IF EXISTS monitoring_sources")
    connection.execute(
        """
        CREATE TABLE monitoring_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'inactive',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "INSERT INTO monitoring_sources (source_name, source_type, status) VALUES (?, ?, ?)",
        ("duplicate source", "APPLICATION", "inactive"),
    )
    connection.execute(
        "INSERT INTO monitoring_sources (source_name, source_type, status) VALUES (?, ?, ?)",
        ("Duplicate Source", "SIMULATION", "inactive"),
    )
    connection.commit()
    connection.close()

    with pytest.warns(RuntimeWarning, match="Duplicate normalized monitoring source names"):
        migrate_database_schema()

    with get_db_connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM monitoring_sources").fetchone()[0] == 2


def test_monitoring_source_allowed_values_are_exposed():
    assert ALLOWED_SOURCE_TYPES == {"FIREBASE", "BLOCKCHAIN", "APPLICATION", "SIMULATION", "OTHER"}
    assert ALLOWED_MONITORING_MODES == {"REAL", "SIMULATED", "PLANNED"}
    assert ALLOWED_CONNECTION_STATUSES == {"NOT_CONNECTED", "CONNECTED", "DEGRADED", "ERROR", "DISABLED"}
