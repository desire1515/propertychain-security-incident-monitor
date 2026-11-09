import json
import uuid
from datetime import datetime, timezone

from database.db import get_db_connection
from backend.services.detection_rule_service import evaluate_security_event


ALLOWED_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical"
}

ALLOWED_CLASSIFICATIONS = {
    "REAL",
    "SIMULATED",
    "TEST"
}


def record_security_event_in_connection(
    connection,
    source,
    event_type,
    severity,
    classification,
    description,
    source_timestamp=None,
    raw_data=None
):
    required_fields = {
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "classification": classification,
        "description": description
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} is required.")

    severity = severity.strip().lower()
    classification = classification.strip().upper()

    if severity not in ALLOWED_SEVERITIES:
        raise ValueError("Invalid event severity.")

    if classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError("Invalid event classification.")

    if source_timestamp is not None:
        if not isinstance(source_timestamp, str) or not source_timestamp.strip():
            raise ValueError("Invalid source timestamp.")

    raw_data_json = (
        json.dumps(raw_data)
        if raw_data is not None
        else None
    )
    event_reference = f"EVT-{uuid.uuid4().hex[:12].upper()}"

    cursor = connection.execute(
        """
        INSERT INTO security_events (
            event_reference,
            source,
            event_type,
            severity,
            classification,
            description,
            source_timestamp,
            raw_data
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_reference,
            source.strip(),
            event_type.strip(),
            severity,
            classification,
            description.strip(),
            source_timestamp,
            raw_data_json
        )
    )
    evaluate_security_event(connection, cursor.lastrowid)
    return event_reference


def record_security_event(
    source,
    event_type,
    severity,
    classification,
    description,
    source_timestamp=None,
    raw_data=None,
):
    with get_db_connection() as connection:
        event_reference = record_security_event_in_connection(
            connection,
            source,
            event_type,
            severity,
            classification,
            description,
            source_timestamp=source_timestamp,
            raw_data=raw_data,
        )
        connection.commit()
    return event_reference


def get_security_events(limit=100):
    """
    Retrieve the latest security events.
    """

    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")

    with get_db_connection() as connection:
        events = connection.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY received_at DESC, id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    return [dict(event) for event in events]
