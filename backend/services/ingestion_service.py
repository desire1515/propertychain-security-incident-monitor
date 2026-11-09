import json
import re
from datetime import datetime

from backend.services.event_service import record_security_event_in_connection
from backend.utils.security import redact_sensitive_text
from database.db import get_db_connection

MAX_BATCH_SIZE = 1000
MAX_EXTERNAL_REFERENCE_LENGTH = 512
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ADAPTERS = {}


def _validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("Ingestion events must be objects.")
    external_reference = event.get("external_reference")
    if (
        not isinstance(external_reference, str)
        or not external_reference.strip()
        or len(external_reference.strip()) > MAX_EXTERNAL_REFERENCE_LENGTH
    ):
        raise ValueError("Invalid external event reference.")

    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_]{0,99}",
        event_type.strip(),
    ):
        raise ValueError("Invalid external event type.")
    severity = event.get("severity")
    if not isinstance(severity, str) or severity.strip().lower() not in ALLOWED_SEVERITIES:
        raise ValueError("Invalid external event severity.")
    description = event.get("description")
    if not isinstance(description, str) or not description.strip() or len(description) > 5000:
        raise ValueError("Invalid external event description.")

    timestamp = event.get("source_timestamp")
    if timestamp is not None:
        if not isinstance(timestamp, str) or not timestamp.strip():
            raise ValueError("Invalid external event timestamp.")
        try:
            datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("Invalid external event timestamp.") from error

    event_data = event.get("raw_data")
    if event_data is not None:
        try:
            encoded = json.dumps(event_data)
        except (TypeError, ValueError) as error:
            raise ValueError("External event metadata must be JSON serializable.") from error
        if len(encoded) > 100_000:
            raise ValueError("External event metadata is too large.")
        event_data = _sanitize_metadata(event_data)

    return {
        "external_reference": external_reference.strip(),
        "event_type": event_type.strip().upper(),
        "severity": severity.strip().lower(),
        "description": redact_sensitive_text(description.strip()),
        "source_timestamp": timestamp.strip() if timestamp else None,
        "raw_data": event_data,
    }


def _sanitize_metadata(value):
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [_sanitize_metadata(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]"
                if re.search(
                    r"(?i)(password|secret|token|api[_-]?key|private[_-]?key|authorization)",
                    str(key),
                )
                else _sanitize_metadata(item)
            )
            for key, item in value.items()
        }
    return value


def _require_active_admin(connection, user_id):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("An active administrator is required.")
    row = connection.execute(
        "SELECT id FROM users WHERE id = ? AND role = 'admin' AND is_active = 1",
        (user_id,),
    ).fetchone()
    if row is None:
        raise ValueError("An active administrator is required.")


def _record_job(connection, source_id, started_by, status="running"):
    cursor = connection.execute(
        """
        INSERT INTO monitoring_ingestion_jobs (source_id, status, started_by)
        VALUES (?, ?, ?)
        """,
        (source_id, status, started_by),
    )
    return cursor.lastrowid


def _finish_job(
    connection,
    job_id,
    status,
    events_seen=0,
    events_ingested=0,
    duplicates_skipped=0,
    error_summary=None,
):
    connection.execute(
        """
        UPDATE monitoring_ingestion_jobs
        SET status = ?,
            events_seen = ?,
            events_ingested = ?,
            duplicates_skipped = ?,
            error_summary = ?,
            completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            status,
            events_seen,
            events_ingested,
            duplicates_skipped,
            redact_sensitive_text(error_summary) if error_summary else None,
            job_id,
        ),
    )


def _record_job_audit(connection, started_by, job_id, status, details):
    connection.execute(
        """
        INSERT INTO system_audit_logs (user_id, action, details)
        VALUES (?, 'MONITORING_INGESTION_JOB', ?)
        """,
        (
            started_by,
            redact_sensitive_text(
                f"Ingestion job {job_id} {status}: {details}"
            ),
        ),
    )


def get_ingestion_jobs(limit=100, source_id=None):
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")
    clauses = []
    parameters = []
    if source_id is not None:
        if type(source_id) is not int or source_id <= 0:
            raise ValueError("Invalid monitoring source ID.")
        clauses.append("j.source_id = ?")
        parameters.append(source_id)
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    parameters.append(limit)
    with get_db_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT j.*, s.source_name, u.username AS started_by_username
            FROM monitoring_ingestion_jobs j
            LEFT JOIN monitoring_sources s ON s.id = j.source_id
            LEFT JOIN users u ON u.id = j.started_by
            {where_clause}
            ORDER BY j.started_at DESC, j.id DESC
            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()
    return [dict(row) for row in rows]


def run_source_poll(source_id, started_by):
    if type(source_id) is not int or source_id <= 0:
        raise ValueError("Invalid monitoring source ID.")
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_active_admin(connection, started_by)
        source = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()
        if source is None:
            raise ValueError("Monitoring source not found.")
        job_id = _record_job(connection, source_id, started_by)

        adapter = ADAPTERS.get(source["source_type"])
        if adapter is None:
            error = (
                f"No verified {source['source_type']} monitoring adapter is "
                "implemented or configured."
            )
            _finish_job(connection, job_id, "unavailable", error_summary=error)
            _record_job_audit(connection, started_by, job_id, "unavailable", error)
            connection.commit()
            return get_ingestion_jobs(source_id=source_id)[0]

        if (
            source["monitoring_mode"] != "REAL"
            or not source["is_enabled"]
            or source["connection_status"] != "CONNECTED"
            or not source["last_successful_check"]
        ):
            error = "Source is not enabled with a verified successful connection."
            _finish_job(connection, job_id, "skipped", error_summary=error)
            _record_job_audit(connection, started_by, job_id, "skipped", error)
            connection.commit()
            return get_ingestion_jobs(source_id=source_id)[0]

    try:
        events = adapter.fetch_events(source_id)
        result = ingest_adapter_events(
            source_id,
            events,
            started_by=started_by,
            existing_job_id=job_id,
        )
    except (OSError, RuntimeError, ValueError) as error:
        safe_error = redact_sensitive_text(str(error)) or "Adapter polling failed."
        with get_db_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            _finish_job(connection, job_id, "failed", error_summary=safe_error)
            _record_job_audit(connection, started_by, job_id, "failed", safe_error)
            connection.commit()
        return get_ingestion_jobs(source_id=source_id)[0]
    return result


def ingest_adapter_events(
    source_id,
    events,
    started_by=None,
    existing_job_id=None,
):
    if type(source_id) is not int or source_id <= 0:
        raise ValueError("Invalid monitoring source ID.")
    if not isinstance(events, (list, tuple)) or len(events) > MAX_BATCH_SIZE:
        raise ValueError("Ingestion batch must contain at most 1000 events.")
    normalized_events = [_validate_event(event) for event in events]
    references = [event["external_reference"] for event in normalized_events]
    if len(references) != len(set(references)):
        raise ValueError("Ingestion batch contains duplicate external references.")

    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if started_by is not None:
            _require_active_admin(connection, started_by)
        source = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()
        if source is None:
            raise ValueError("Monitoring source not found.")
        if (
            source["monitoring_mode"] != "REAL"
            or not source["is_enabled"]
            or source["connection_status"] != "CONNECTED"
            or not source["last_successful_check"]
        ):
            raise ValueError("Source is not enabled with a verified successful connection.")

        job_id = existing_job_id or _record_job(
            connection,
            source_id,
            started_by,
        )
        ingested = 0
        duplicates = 0
        for event in normalized_events:
            duplicate = connection.execute(
                """
                SELECT id FROM monitoring_ingested_events
                WHERE source_id = ? AND external_reference = ?
                """,
                (source_id, event["external_reference"]),
            ).fetchone()
            if duplicate is not None:
                duplicates += 1
                continue
            event_reference = record_security_event_in_connection(
                connection,
                source=source["source_name"],
                event_type=event["event_type"],
                severity=event["severity"],
                classification="REAL",
                description=event["description"],
                source_timestamp=event["source_timestamp"],
                raw_data={
                    "external_reference": event["external_reference"],
                    "adapter_metadata": event["raw_data"],
                },
            )
            event_row = connection.execute(
                "SELECT id FROM security_events WHERE event_reference = ?",
                (event_reference,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO monitoring_ingested_events (
                    source_id, external_reference, event_id
                )
                VALUES (?, ?, ?)
                """,
                (source_id, event["external_reference"], event_row["id"]),
            )
            ingested += 1

        _finish_job(
            connection,
            job_id,
            "completed",
            events_seen=len(normalized_events),
            events_ingested=ingested,
            duplicates_skipped=duplicates,
        )
        _record_job_audit(
            connection,
            started_by,
            job_id,
            "completed",
            f"{ingested} event(s) ingested; {duplicates} duplicate(s) skipped.",
        )
        connection.commit()
    return next(
        job
        for job in get_ingestion_jobs(source_id=source_id)
        if job["id"] == job_id
    )


def run_ingestion_cycle(started_by=None):
    if started_by is not None:
        with get_db_connection() as connection:
            _require_active_admin(connection, started_by)
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT id FROM monitoring_sources
            WHERE is_enabled = 1 AND monitoring_mode = 'REAL'
            ORDER BY id
            """
        ).fetchall()
    return [
        run_source_poll(row["id"], started_by)
        for row in rows
    ]


if __name__ == "__main__":
    from app import app
    from database.db import initialize_database

    with app.app_context():
        initialize_database()
        jobs = run_ingestion_cycle()
    for job in jobs:
        print(
            f"Source {job['source_name']}: {job['status']} "
            f"({job['events_ingested']} events)"
        )
    if not jobs:
        print("No enabled real monitoring sources are available to poll.")
