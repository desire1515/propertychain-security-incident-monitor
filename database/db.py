import sqlite3
import warnings
from pathlib import Path

from flask import current_app, has_app_context

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_DIR = PROJECT_ROOT / "instance"
DATABASE_PATH = DATABASE_DIR / "pcsirm.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exception_type, exception, traceback):
        try:
            return super().__exit__(exception_type, exception, traceback)
        finally:
            self.close()


def _configured_database_path():
    if has_app_context():
        return Path(current_app.config.get("DATABASE_PATH", DATABASE_PATH))

    return DATABASE_PATH


def _ensure_monitoring_source_columns(connection):
    columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info(monitoring_sources)"
        ).fetchall()
    }

    additions = [
        ("description", "TEXT"),
        ("monitoring_mode", "TEXT"),
        ("connection_status", "TEXT"),
        ("is_enabled", "INTEGER"),
        ("last_checked_at", "TEXT"),
        ("last_successful_check", "TEXT"),
        ("last_error", "TEXT"),
        ("updated_at", "TEXT"),
        ("created_by", "INTEGER"),
        ("updated_by", "INTEGER"),
    ]

    for column_name, definition in additions:
        if column_name not in columns:
            connection.execute(
                f"ALTER TABLE monitoring_sources ADD COLUMN {column_name} {definition}"
            )

    connection.execute(
        """
        UPDATE monitoring_sources
        SET description = COALESCE(description, NULL),
            monitoring_mode = COALESCE(monitoring_mode, 'PLANNED'),
            connection_status = COALESCE(connection_status, 'NOT_CONNECTED'),
            is_enabled = CASE WHEN is_enabled IS NULL THEN 0 ELSE CAST(is_enabled AS INTEGER) END,
            updated_at = CASE WHEN updated_at IS NULL OR TRIM(updated_at) = '' THEN CURRENT_TIMESTAMP ELSE updated_at END
        WHERE monitoring_mode IS NULL
           OR connection_status IS NULL
           OR is_enabled IS NULL
           OR updated_at IS NULL
        """
    )

    connection.execute(
        """
        UPDATE monitoring_sources
        SET status = CASE
            WHEN CAST(is_enabled AS INTEGER) = 1 AND connection_status IN ('CONNECTED', 'DEGRADED') THEN 'active'
            ELSE 'inactive'
        END,
            updated_at = CASE WHEN updated_at IS NULL OR TRIM(updated_at) = '' THEN CURRENT_TIMESTAMP ELSE updated_at END
        WHERE status IS NULL OR status NOT IN ('active', 'inactive')
        """
    )

    duplicate_rows = connection.execute(
        """
        SELECT LOWER(TRIM(source_name)) AS normalized_name, COUNT(*) AS occurrences
        FROM monitoring_sources
        WHERE source_name IS NOT NULL
        GROUP BY LOWER(TRIM(source_name))
        HAVING COUNT(*) > 1
        ORDER BY normalized_name
        """
    ).fetchall()

    if duplicate_rows:
        names = ", ".join(row[0] for row in duplicate_rows)
        warnings.warn(
            "Duplicate normalized monitoring source names detected: "
            f"{names}. Unique index creation skipped to preserve existing records.",
            RuntimeWarning,
        )
        return

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_monitoring_sources_name_normalized
        ON monitoring_sources (LOWER(TRIM(source_name)))
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitoring_sources_status
        ON monitoring_sources (status)
        """
    )


def _ensure_detection_rule_columns(connection):
    columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info(detection_rules)"
        ).fetchall()
    }

    additions = [
        ("threshold", "INTEGER NOT NULL DEFAULT 1"),
        ("window_minutes", "INTEGER NOT NULL DEFAULT 60"),
        ("created_by", "INTEGER"),
        ("updated_at", "TEXT"),
    ]
    for column_name, definition in additions:
        if column_name not in columns:
            connection.execute(
                f"ALTER TABLE detection_rules ADD COLUMN {column_name} {definition}"
            )

    connection.execute(
        """
        UPDATE detection_rules
        SET threshold = CASE
                WHEN threshold IS NULL OR threshold < 1 THEN 1
                ELSE threshold
            END,
            window_minutes = CASE
                WHEN window_minutes IS NULL OR window_minutes < 1 THEN 60
                ELSE window_minutes
            END,
            updated_at = COALESCE(NULLIF(TRIM(updated_at), ''), created_at, CURRENT_TIMESTAMP)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_detection_rule_executions_event
        ON detection_rule_executions (event_id)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_detection_alerts_status
        ON detection_alerts (status, created_at)
        """
    )


def _ensure_simulation_run_columns(connection):
    columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info(simulation_runs)"
        ).fetchall()
    }
    if "executed_by" not in columns:
        connection.execute(
            "ALTER TABLE simulation_runs ADD COLUMN executed_by INTEGER"
        )


def _ensure_incident_workflow_columns(connection):
    additions_by_table = {
        "incident_evidence": [
            ("collected_by", "INTEGER"),
            ("evidence_reference", "TEXT"),
            ("original_filename", "TEXT"),
            ("storage_path", "TEXT"),
            ("file_size", "INTEGER"),
            ("mime_type", "TEXT"),
            ("sha256_hash", "TEXT"),
        ],
        "incident_actions": [
            ("updated_by", "INTEGER"),
            ("updated_at", "TEXT"),
            ("completed_at", "TEXT"),
        ],
    }
    for table_name, additions in additions_by_table.items():
        columns = {
            row[1] for row in connection.execute(
                f"PRAGMA table_info({table_name})"
            ).fetchall()
        }
        for column_name, definition in additions:
            if column_name not in columns:
                connection.execute(
                    f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
                )

    connection.execute(
        """
        UPDATE incident_actions
        SET updated_at = COALESCE(
            NULLIF(TRIM(updated_at), ''),
            created_at,
            CURRENT_TIMESTAMP
        )
        WHERE updated_at IS NULL OR TRIM(updated_at) = ''
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident
        ON incident_evidence (incident_id)
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_incident_actions_incident
        ON incident_actions (incident_id)
        """
    )
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_evidence_reference
        ON incident_evidence (evidence_reference)
        WHERE evidence_reference IS NOT NULL
        """
    )


def migrate_database_schema():
    with get_db_connection() as connection:
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
        connection.executescript(schema)
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='monitoring_sources'"
        ).fetchone():
            _ensure_monitoring_source_columns(connection)
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='detection_rules'"
        ).fetchone():
            _ensure_detection_rule_columns(connection)
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='simulation_runs'"
        ).fetchone():
            _ensure_simulation_run_columns(connection)
        if connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='incident_evidence'"
        ).fetchone():
            _ensure_incident_workflow_columns(connection)
        connection.execute(
            """
            INSERT INTO detection_alert_history (
                alert_id, previous_status, new_status, changed_by, changed_at
            )
            SELECT a.id, NULL, a.status, NULL, a.created_at
            FROM detection_alerts a
            WHERE NOT EXISTS (
                SELECT 1 FROM detection_alert_history h
                WHERE h.alert_id = a.id
            )
            """
        )
        connection.commit()


def get_db_connection():
    database_path = _configured_database_path()
    database_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path, factory=ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    migrate_database_schema()
    from backend.services.detection_rule_service import ensure_default_detection_rules

    ensure_default_detection_rules()


if __name__ == "__main__":
    initialize_database()
    print(f"PCSIRM database initialized: {_configured_database_path()}")
