import sqlite3
import tempfile
from pathlib import Path

import pytest

from app import app as module_app
from app import create_app
from backend.services.auth_service import create_user
from backend.services.event_service import record_security_event
from config import Config
from database.db import get_db_connection, initialize_database


DEVELOPMENT_DATABASE_PATH = Path(Config.DATABASE_PATH).resolve()
PROTECTED_TABLES = (
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
)


def _read_only_development_snapshot():
    if not DEVELOPMENT_DATABASE_PATH.exists():
        return {
            "exists": False,
            "modified_ns": None,
            "rows": {},
        }

    connection = sqlite3.connect(
        f"{DEVELOPMENT_DATABASE_PATH.as_uri()}?mode=ro",
        uri=True,
    )
    try:
        existing_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        rows = {}
        for table in PROTECTED_TABLES:
            rows[table] = (
                connection.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
                if table in existing_tables
                else None
            )
    finally:
        connection.close()

    return {
        "exists": True,
        "modified_ns": DEVELOPMENT_DATABASE_PATH.stat().st_mtime_ns,
        "rows": rows,
    }


@pytest.fixture(scope="session", autouse=True)
def development_database_guard():
    before = _read_only_development_snapshot()
    yield before
    after = _read_only_development_snapshot()

    assert after["exists"] == before["exists"], (
        "The development database file existence changed during pytest."
    )
    assert after["modified_ns"] == before["modified_ns"], (
        "The development database modification timestamp changed during pytest."
    )
    assert after["rows"] == before["rows"], (
        "Development database rows changed during pytest."
    )


@pytest.fixture(scope="session", autouse=True)
def isolate_module_level_app(tmp_path_factory, development_database_guard):
    database_path = tmp_path_factory.mktemp("pcsirm-module-app") / "test.db"
    module_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-only-module-secret",
        "SESSION_COOKIE_SECURE": False,
        "DATABASE_PATH": database_path,
    })
    with module_app.app_context():
        initialize_database()
    module_app.extensions["database_initialized"] = True
    yield


@pytest.fixture(autouse=True)
def app():
    with tempfile.TemporaryDirectory(prefix="pcsirm-test-") as directory:
        database_path = Path(directory) / "pcsirm-test.db"
        application = create_app({
            "TESTING": True,
            "SECRET_KEY": "test-only-secret-key",
            "SESSION_COOKIE_SECURE": False,
            "DATABASE_PATH": database_path,
        })

        context = application.app_context()
        context.push()
        try:
            yield application
        finally:
            context.pop()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def database(app):
    connection = get_db_connection()
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def test_user(database):
    username = "test-admin"
    password = "test-admin-password-123"
    create_user(username, password, role="admin")
    user = database.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "password": password,
    }


@pytest.fixture
def analyst(database):
    username = "test-analyst"
    password = "test-analyst-password-123"
    create_user(username, password, role="analyst")
    user = database.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "password": password,
    }


@pytest.fixture
def test_event(database):
    reference = record_security_event(
        source="PCSIRM Test Source",
        event_type="TEST_LOGIN_FAILURE",
        severity="high",
        classification="TEST",
        description="A test security event for isolated incident tests.",
    )
    event = database.execute(
        "SELECT * FROM security_events WHERE event_reference = ?",
        (reference,),
    ).fetchone()
    return dict(event)


@pytest.fixture
def authenticated_client(client, test_user):
    with client.session_transaction() as session:
        session["user_id"] = test_user["id"]
        session["username"] = test_user["username"]
        session["role"] = test_user["role"]
        session["csrf_token"] = "test-csrf-token"
    return client
