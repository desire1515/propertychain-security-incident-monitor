
import hashlib
import mimetypes
import os
import sqlite3
import uuid
from pathlib import Path

from flask import current_app, has_app_context
from backend.utils.security import redact_sensitive_text
from database.db import get_db_connection
from werkzeug.utils import secure_filename


ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}
ALLOWED_CLASSIFICATIONS = {"REAL", "SIMULATED", "TEST"}
ALLOWED_STATUSES = {
    "open", "investigating", "contained", "resolved", "closed"
}
ALLOWED_EVIDENCE_TYPES = {
    "LOG", "SCREENSHOT", "DOCUMENT", "HASH", "REFERENCE", "OTHER"
}
ALLOWED_ACTION_TYPES = {"RECOMMENDATION", "SIMULATION"}
ALLOWED_ACTION_STATUSES = {
    "proposed", "approved", "in_progress", "completed", "cancelled"
}
ACTION_STATUS_TRANSITIONS = {
    "proposed": {"approved", "cancelled"},
    "approved": {"in_progress", "cancelled"},
    "in_progress": {"completed", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}
MAX_EVIDENCE_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EVIDENCE_FILE_EXTENSIONS = {
    ".csv", ".jpeg", ".jpg", ".log", ".pdf", ".png", ".txt"
}


def _evidence_storage_root():
    if has_app_context():
        configured_path = current_app.config.get("EVIDENCE_STORAGE_PATH")
        if configured_path:
            return Path(configured_path).resolve()
        database_path = Path(current_app.config["DATABASE_PATH"])
    else:
        from database.db import DATABASE_PATH

        database_path = DATABASE_PATH
    return (database_path.parent / "private_evidence").resolve()


def _store_evidence_file(file_stream, filename):
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Evidence filename is required.")
    display_filename = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    storage_filename = secure_filename(display_filename)
    extension = Path(storage_filename).suffix.lower()
    if not storage_filename or extension not in ALLOWED_EVIDENCE_FILE_EXTENSIONS:
        raise ValueError("Evidence file type is not allowed.")

    content = bytearray()
    while True:
        chunk = file_stream.read(64 * 1024)
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            raise ValueError("Evidence file must contain binary data.")
        if len(content) + len(chunk) > MAX_EVIDENCE_FILE_SIZE:
            raise ValueError("Evidence file exceeds the 10 MB limit.")
        content.extend(chunk)
    if not content:
        raise ValueError("Evidence file cannot be empty.")

    payload = bytes(content)
    if extension == ".pdf" and not payload.startswith(b"%PDF-"):
        raise ValueError("Evidence file content does not match its PDF extension.")
    if extension == ".png" and not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Evidence file content does not match its PNG extension.")
    if extension in {".jpg", ".jpeg"} and not payload.startswith(b"\xff\xd8\xff"):
        raise ValueError("Evidence file content does not match its image extension.")
    if extension in {".txt", ".log", ".csv"}:
        if b"\x00" in payload:
            raise ValueError("Text evidence cannot contain binary data.")
        try:
            payload.decode("utf-8-sig")
        except UnicodeDecodeError as error:
            raise ValueError("Text evidence must use UTF-8 encoding.") from error

    evidence_reference = f"EVD-{uuid.uuid4().hex[:16].upper()}"
    relative_path = f"{evidence_reference}{extension}"
    storage_root = _evidence_storage_root()
    storage_root.mkdir(parents=True, exist_ok=True)
    destination = (storage_root / relative_path).resolve()
    if storage_root not in destination.parents:
        raise ValueError("Invalid evidence storage path.")

    with destination.open("xb") as evidence_file:
        evidence_file.write(payload)
        evidence_file.flush()
        os.fsync(evidence_file.fileno())

    return {
        "reference": evidence_reference,
        "original_filename": display_filename[:255],
        "storage_path": relative_path,
        "file_size": len(payload),
        "mime_type": (
            "text/csv"
            if extension == ".csv"
            else mimetypes.guess_type(storage_filename)[0]
            or "application/octet-stream"
        ),
        "sha256_hash": hashlib.sha256(payload).hexdigest(),
        "path": destination,
    }


def _resolve_evidence_path(storage_path):
    if not isinstance(storage_path, str) or not storage_path:
        raise ValueError("Evidence file is unavailable.")
    storage_root = _evidence_storage_root()
    evidence_path = (storage_root / storage_path).resolve()
    if storage_root not in evidence_path.parents or not evidence_path.is_file():
        raise ValueError("Evidence file is unavailable.")
    return evidence_path


def _record_evidence_custody(
    connection,
    evidence_id,
    action,
    actor_id,
    details,
):
    connection.execute(
        """
        INSERT INTO incident_evidence_custody (
            evidence_id, action, actor_id, details
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            evidence_id,
            action,
            actor_id,
            redact_sensitive_text(details) if details else None,
        ),
    )


def _validate_incident_data(title, severity, classification):
    if not isinstance(title, str) or not title.strip():
        raise ValueError("Incident title is required.")

    if len(title.strip()) > 200:
        raise ValueError("Incident title cannot exceed 200 characters.")

    if not isinstance(severity, str):
        raise ValueError("Invalid incident severity.")

    severity = severity.strip().lower()
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError("Invalid incident severity.")

    if not isinstance(classification, str):
        raise ValueError("Invalid incident classification.")

    classification = classification.strip().upper()
    if classification not in ALLOWED_CLASSIFICATIONS:
        raise ValueError("Invalid incident classification.")

    return severity, classification


def _validate_user(connection, user_id, error_message):
    if user_id is None:
        return

    if type(user_id) is not int or user_id <= 0:
        raise ValueError(error_message)

    user = connection.execute(
        "SELECT id FROM users WHERE id = ? AND is_active = 1",
        (user_id,)
    ).fetchone()

    if user is None:
        raise ValueError(error_message)


def _validate_assignee(connection, assigned_to):
    _validate_user(
        connection, assigned_to,
        "Assigned user does not exist or is inactive."
    )


def _validate_actor(connection, user_id):
    _validate_user(
        connection, user_id,
        "Acting user does not exist or is inactive."
    )


def _require_actor_role(connection, user_id, allowed_roles, error_message):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError(error_message)
    actor = connection.execute(
        "SELECT role FROM users WHERE id = ? AND is_active = 1",
        (user_id,),
    ).fetchone()
    if actor is None or actor["role"] not in allowed_roles:
        raise ValueError(error_message)
    return actor["role"]


def _record_timeline(connection, incident_id, activity, details):
    connection.execute(
        """
        INSERT INTO incident_timeline (incident_id, activity, details)
        VALUES (?, ?, ?)
        """,
        (incident_id, activity, details)
    )


def _record_audit(connection, user_id, action, details):
    connection.execute(
        """
        INSERT INTO system_audit_logs (user_id, action, details)
        VALUES (?, ?, ?)
        """,
        (user_id, action, details)
    )


def create_incident(
    title, description, severity, classification,
    assigned_to=None, source_event_id=None, created_by=None
):
    severity, classification = _validate_incident_data(
        title, severity, classification
    )

    if description is not None:
        if not isinstance(description, str):
            raise ValueError("Invalid incident description.")
        if len(description) > 5000:
            raise ValueError("Incident description is too long.")

    if source_event_id is not None:
        if type(source_event_id) is not int or source_event_id <= 0:
            raise ValueError("Invalid source event ID.")

    incident_reference = f"INC-{uuid.uuid4().hex[:12].upper()}"

    try:
        with get_db_connection() as connection:
            actor_role = _require_actor_role(
                connection,
                created_by,
                {"admin", "analyst"},
                "An active administrator or analyst is required to create incidents.",
            )
            if assigned_to is not None and actor_role != "admin":
                raise ValueError("Only administrators may assign incidents.")
            _validate_assignee(connection, assigned_to)

            if source_event_id is not None:
                event = connection.execute(
                    "SELECT id FROM security_events WHERE id = ?",
                    (source_event_id,)
                ).fetchone()

                if event is None:
                    raise ValueError("Source security event not found.")

            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    incident_reference, title, description, severity,
                    classification, assigned_to, source_event_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_reference,
                    title.strip(),
                    description.strip() if description else None,
                    severity,
                    classification,
                    assigned_to,
                    source_event_id
                )
            )

            incident_id = cursor.lastrowid

            _record_timeline(
                connection, incident_id,
                "Incident created",
                f"Incident {incident_reference} was created."
            )

            _record_audit(
                connection, created_by,
                "INCIDENT_CREATED",
                f"Incident {incident_reference} was created."
            )

        return incident_reference

    except sqlite3.IntegrityError as error:
        if source_event_id is not None:
            raise ValueError(
                "This security event may already be linked to an incident "
                "or a database constraint was violated."
            ) from error

        raise ValueError(
            "Incident could not be created because of a database constraint."
        ) from error


def create_incident_from_event(
    event_reference,
    assigned_to=None,
    created_by=None,
    title=None,
    description=None,
    severity=None,
):
    if not isinstance(event_reference, str) or not event_reference.strip():
        raise ValueError("Event reference is required.")

    with get_db_connection() as connection:
        _require_actor_role(
            connection,
            created_by,
            {"admin", "analyst"},
            "An active administrator or analyst is required to create incidents.",
        )
        event = connection.execute(
            """
            SELECT *
            FROM security_events
            WHERE event_reference = ?
            """,
            (event_reference.strip(),)
        ).fetchone()

        if event is None:
            raise ValueError("Security event not found.")

        event_data = dict(event)

    existing_incident = get_incident_by_event_reference(
        event_data["event_reference"]
    )
    if existing_incident is not None:
        raise ValueError("This security event may already be linked to an incident.")

    incident_title = title
    if incident_title is None:
        incident_title = (
            f"{event_data['event_type'].replace('_', ' ').title()} "
            f"- {event_data['event_reference']}"
        )
    incident_description = description
    if incident_description is None:
        incident_description = (
            f"Originating security event: {event_data['event_reference']}\n"
            f"Source: {event_data['source']}\n"
            f"Event description: {event_data['description']}"
        )

    return create_incident(
        title=incident_title,
        description=incident_description,
        severity=event_data["severity"] if severity is None else severity,
        classification=event_data["classification"],
        assigned_to=assigned_to,
        source_event_id=event_data["id"],
        created_by=created_by
    )


def get_incidents():
    with get_db_connection() as connection:
        incidents = connection.execute(
            """
            SELECT
                i.*,
                u.username AS assigned_username,
                e.event_reference AS source_event_reference,
                e.event_type AS source_event_type
            FROM incidents i
            LEFT JOIN users u ON i.assigned_to = u.id
            LEFT JOIN security_events e ON i.source_event_id = e.id
            ORDER BY i.created_at DESC, i.id DESC
            """
        ).fetchall()

    return [dict(incident) for incident in incidents]


def get_incident_by_reference(incident_reference):
    if not isinstance(incident_reference, str):
        return None

    with get_db_connection() as connection:
        incident = connection.execute(
            """
            SELECT
                i.*,
                u.username AS assigned_username,
                e.event_reference AS source_event_reference,
                e.event_type AS source_event_type
            FROM incidents i
            LEFT JOIN users u ON i.assigned_to = u.id
            LEFT JOIN security_events e ON i.source_event_id = e.id
            WHERE i.incident_reference = ?
            """,
            (incident_reference.strip(),)
        ).fetchone()

    return dict(incident) if incident else None


def get_incident_by_event_reference(event_reference):
    if not isinstance(event_reference, str) or not event_reference.strip():
        return None

    with get_db_connection() as connection:
        incident = connection.execute(
            """
            SELECT i.incident_reference, i.title
            FROM incidents i
            JOIN security_events e ON e.id = i.source_event_id
            WHERE e.event_reference = ?
            """,
            (event_reference.strip(),),
        ).fetchone()
    return dict(incident) if incident else None


def get_assignable_incident_users():
    with get_db_connection() as connection:
        users = connection.execute(
            """
            SELECT id, username
            FROM users
            WHERE is_active = 1 AND role = 'analyst'
            ORDER BY username COLLATE NOCASE, id
            """
        ).fetchall()
    return [dict(user) for user in users]


def assign_incident(incident_reference, assigned_to, assigned_by):
    if not isinstance(incident_reference, str) or not incident_reference.strip():
        raise ValueError("Incident reference is required.")
    if assigned_to is not None and (type(assigned_to) is not int or assigned_to <= 0):
        raise ValueError("Select an active analyst or choose unassigned.")
    if type(assigned_by) is not int or assigned_by <= 0:
        raise ValueError("An active administrator is required to assign incidents.")

    with get_db_connection() as connection:
        _require_actor_role(
            connection,
            assigned_by,
            {"admin"},
            "An active administrator is required to assign incidents.",
        )

        incident = connection.execute(
            """
            SELECT id, incident_reference, assigned_to
            FROM incidents
            WHERE incident_reference = ?
            """,
            (incident_reference.strip(),),
        ).fetchone()
        if incident is None:
            raise ValueError("Incident not found.")

        assignee = None
        if assigned_to is not None:
            assignee = connection.execute(
                """
                SELECT id, username FROM users
                WHERE id = ? AND is_active = 1 AND role = 'analyst'
                """,
                (assigned_to,),
            ).fetchone()
            if assignee is None:
                raise ValueError("Selected assignee does not exist, is inactive, or is not an analyst.")

        old_assigned_to = incident["assigned_to"]
        if old_assigned_to == assigned_to:
            return False

        previous_assignee = None
        if old_assigned_to is not None:
            previous_assignee = connection.execute(
                "SELECT username FROM users WHERE id = ?",
                (old_assigned_to,),
            ).fetchone()
        old_username = previous_assignee["username"] if previous_assignee else None
        new_username = assignee["username"] if assignee else None

        connection.execute(
            """
            UPDATE incidents
            SET assigned_to = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (assigned_to, incident["id"]),
        )

        if assigned_to is None:
            activity = "Incident unassigned"
            details = f"Incident {incident['incident_reference']} was unassigned from {old_username or 'the previous analyst'}."
            audit_action = "INCIDENT_UNASSIGNED"
        elif old_assigned_to is None:
            activity = "Incident assigned"
            details = f"Incident {incident['incident_reference']} was assigned to {new_username}."
            audit_action = "INCIDENT_ASSIGNED"
        else:
            activity = "Incident reassigned"
            details = (
                f"Incident {incident['incident_reference']} was reassigned "
                f"from {old_username or 'the previous analyst'} to {new_username}."
            )
            audit_action = "INCIDENT_REASSIGNED"

        _record_timeline(connection, incident["id"], activity, details)
        _record_audit(connection, assigned_by, audit_action, details)
        connection.commit()
    return True


def update_incident_status(
    incident_reference, new_status, updated_by=None
):
    if not isinstance(incident_reference, str) or not incident_reference.strip():
        raise ValueError("Incident reference is required.")

    if not isinstance(new_status, str):
        raise ValueError("Invalid incident status.")

    new_status = new_status.strip().lower()
    if new_status not in ALLOWED_STATUSES:
        raise ValueError("Invalid incident status.")

    with get_db_connection() as connection:
        _validate_actor(connection, updated_by)

        incident = connection.execute(
            """
            SELECT id, status
            FROM incidents
            WHERE incident_reference = ?
            """,
            (incident_reference.strip(),)
        ).fetchone()

        if incident is None:
            raise ValueError("Incident not found.")

        _require_actor_role(
            connection,
            updated_by,
            {"admin"},
            "Only active administrators may change incident status.",
        )

        old_status = incident["status"]

        if old_status == new_status:
            return False

        connection.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (new_status, incident["id"])
        )

        _record_timeline(
            connection, incident["id"],
            "Status changed",
            f"Incident status changed from {old_status} to {new_status}."
        )

        _record_audit(
            connection, updated_by,
            "INCIDENT_STATUS_UPDATED",
            f"{incident_reference}: {old_status} -> {new_status}"
        )

    return True


def add_incident_evidence(
    incident_id,
    evidence_type,
    description,
    evidence_data=None,
    collected_by=None,
    file_stream=None,
    original_filename=None,
):
    if type(incident_id) is not int or incident_id <= 0:
        raise ValueError("Invalid incident ID.")
    if not isinstance(evidence_type, str):
        raise ValueError("Invalid evidence type.")
    normalized_type = evidence_type.strip().upper()
    if normalized_type not in ALLOWED_EVIDENCE_TYPES:
        raise ValueError("Invalid evidence type.")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("Evidence description is required.")
    if len(description.strip()) > 2000:
        raise ValueError("Evidence description cannot exceed 2000 characters.")
    if evidence_data is not None:
        if not isinstance(evidence_data, str):
            raise ValueError("Evidence data or reference must be text.")
        if len(evidence_data) > 5000:
            raise ValueError("Evidence data or reference cannot exceed 5000 characters.")

    safe_description = redact_sensitive_text(description.strip())
    safe_evidence_data = redact_sensitive_text(evidence_data)

    if file_stream is not None and not original_filename:
        raise ValueError("Evidence filename is required.")
    if file_stream is None and original_filename is not None:
        raise ValueError("Evidence file content is required.")

    evidence_file = None
    committed = False
    try:
        with get_db_connection() as connection:
            if type(collected_by) is not int or collected_by <= 0:
                raise ValueError("An active user is required to collect evidence.")
            _require_actor_role(
                connection,
                collected_by,
                {"admin", "analyst"},
                "Only active administrators and analysts may register evidence.",
            )
            incident = connection.execute(
                "SELECT id, incident_reference FROM incidents WHERE id = ?",
                (incident_id,),
            ).fetchone()
            if incident is None:
                raise ValueError("Incident not found.")

            if file_stream is not None:
                evidence_file = _store_evidence_file(
                    file_stream,
                    original_filename,
                )
            else:
                evidence_file = {
                    "reference": f"EVD-{uuid.uuid4().hex[:16].upper()}",
                    "original_filename": None,
                    "storage_path": None,
                    "file_size": None,
                    "mime_type": None,
                    "sha256_hash": None,
                    "path": None,
                }

            cursor = connection.execute(
                """
                INSERT INTO incident_evidence (
                    incident_id, evidence_type, description, evidence_data,
                    collected_by, evidence_reference, original_filename,
                    storage_path, file_size, mime_type, sha256_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    normalized_type,
                    safe_description,
                    safe_evidence_data,
                    collected_by,
                    evidence_file["reference"],
                    evidence_file["original_filename"],
                    evidence_file["storage_path"],
                    evidence_file["file_size"],
                    evidence_file["mime_type"],
                    evidence_file["sha256_hash"],
                ),
            )
            evidence_id = cursor.lastrowid
            _record_evidence_custody(
                connection,
                evidence_id,
                "REGISTERED",
                collected_by,
                f"Evidence record {evidence_file['reference']} registered.",
            )
            if file_stream is not None:
                _record_evidence_custody(
                    connection,
                    evidence_id,
                    "UPLOADED",
                    collected_by,
                    (
                        f"File {evidence_file['original_filename']} uploaded; "
                        f"SHA-256 {evidence_file['sha256_hash']}."
                    ),
                )
            _record_timeline(
                connection,
                incident_id,
                "Evidence collected",
                f"Evidence record {evidence_id} ({normalized_type}) was added.",
            )
            _record_audit(
                connection,
                collected_by,
                "INCIDENT_EVIDENCE_COLLECTED",
                f"Evidence record {evidence_id} added to {incident['incident_reference']}.",
            )
            connection.commit()
            committed = True
    finally:
        if not committed and evidence_file and evidence_file["path"]:
            evidence_file["path"].unlink(missing_ok=True)
    return evidence_id


def get_incident_evidence(incident_id):
    if type(incident_id) is not int or incident_id <= 0:
        return []
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT e.*, u.username AS collected_by_username
            FROM incident_evidence e
            LEFT JOIN users u ON u.id = e.collected_by
            WHERE e.incident_id = ?
            ORDER BY e.collected_at, e.id
            """,
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_incident_evidence_by_id(evidence_id):
    if type(evidence_id) is not int or evidence_id <= 0:
        return None
    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT e.*, i.incident_reference
            FROM incident_evidence e
            JOIN incidents i ON i.id = e.incident_id
            WHERE e.id = ?
            """,
            (evidence_id,),
        ).fetchone()
    return dict(row) if row else None


def get_incident_evidence_custody(evidence_id):
    if type(evidence_id) is not int or evidence_id <= 0:
        return []
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT c.*, u.username AS actor_username
            FROM incident_evidence_custody c
            LEFT JOIN users u ON u.id = c.actor_id
            WHERE c.evidence_id = ?
            ORDER BY c.recorded_at, c.id
            """,
            (evidence_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def verify_incident_evidence(evidence_id, verified_by):
    if type(verified_by) is not int or verified_by <= 0:
        raise ValueError("An active user is required to verify evidence.")
    with get_db_connection() as connection:
        _require_actor_role(
            connection,
            verified_by,
            {"admin", "analyst"},
            "Only active administrators and analysts may verify evidence.",
        )
        evidence = connection.execute(
            """
            SELECT e.*, i.incident_reference
            FROM incident_evidence e
            JOIN incidents i ON i.id = e.incident_id
            WHERE e.id = ?
            """,
            (evidence_id,),
        ).fetchone()
        if evidence is None:
            raise ValueError("Evidence record not found.")
        if not evidence["storage_path"] or not evidence["sha256_hash"]:
            raise ValueError("Evidence record has no uploaded file to verify.")

    evidence_path = _resolve_evidence_path(evidence["storage_path"])
    digest = hashlib.sha256()
    try:
        with evidence_path.open("rb") as evidence_file:
            for chunk in iter(lambda: evidence_file.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        verified = False
        actual_hash = None
        details = f"Evidence {evidence['evidence_reference']} file could not be read."
    else:
        actual_hash = digest.hexdigest()
        verified = actual_hash == evidence["sha256_hash"]
        details = (
            f"Evidence {evidence['evidence_reference']} integrity "
            f"{'verified' if verified else 'mismatch'}; "
            f"SHA-256 {actual_hash}."
        )

    with get_db_connection() as connection:
        _record_evidence_custody(
            connection,
            evidence_id,
            "VERIFIED" if verified else "INTEGRITY_MISMATCH",
            verified_by,
            details,
        )
        _record_timeline(
            connection,
            evidence["incident_id"],
            "Evidence integrity checked",
            details,
        )
        _record_audit(
            connection,
            verified_by,
            "INCIDENT_EVIDENCE_VERIFIED" if verified else "INCIDENT_EVIDENCE_INTEGRITY_MISMATCH",
            f"{evidence['incident_reference']}: {details}",
        )
        connection.commit()
    return {
        "verified": verified,
        "expected_sha256": evidence["sha256_hash"],
        "actual_sha256": actual_hash,
    }


def record_incident_evidence_access(evidence_id, accessed_by):
    if type(accessed_by) is not int or accessed_by <= 0:
        raise ValueError("An active user is required to access evidence.")
    with get_db_connection() as connection:
        _require_actor_role(
            connection,
            accessed_by,
            {"admin", "analyst"},
            "Only active administrators and analysts may access evidence.",
        )
        evidence = connection.execute(
            """
            SELECT e.*, i.incident_reference
            FROM incident_evidence e
            JOIN incidents i ON i.id = e.incident_id
            WHERE e.id = ?
            """,
            (evidence_id,),
        ).fetchone()
        if evidence is None:
            raise ValueError("Evidence record not found.")
        if not evidence["storage_path"]:
            raise ValueError("Evidence record has no uploaded file.")
        evidence_path = _resolve_evidence_path(evidence["storage_path"])
        details = f"Evidence {evidence['evidence_reference']} file accessed."
        _record_evidence_custody(
            connection,
            evidence_id,
            "ACCESSED",
            accessed_by,
            details,
        )
        _record_audit(
            connection,
            accessed_by,
            "INCIDENT_EVIDENCE_ACCESSED",
            f"{evidence['incident_reference']}: {details}",
        )
        connection.commit()
    return dict(evidence), evidence_path


def add_incident_action(
    incident_id,
    action_type,
    description,
    performed_by=None,
):
    if type(incident_id) is not int or incident_id <= 0:
        raise ValueError("Invalid incident ID.")
    if not isinstance(action_type, str):
        raise ValueError("Invalid response action type.")
    normalized_type = action_type.strip().upper()
    if normalized_type not in ALLOWED_ACTION_TYPES:
        raise ValueError("Only recommendations or controlled simulations may be recorded.")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("Response action description is required.")
    if len(description.strip()) > 2000:
        raise ValueError("Response action description cannot exceed 2000 characters.")
    safe_description = redact_sensitive_text(description.strip())

    with get_db_connection() as connection:
        if type(performed_by) is not int or performed_by <= 0:
            raise ValueError("An active user is required to record a response action.")
        _require_actor_role(
            connection,
            performed_by,
            {"admin", "analyst"},
            "Only active administrators and analysts may record response actions.",
        )
        incident = connection.execute(
            "SELECT id, incident_reference FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise ValueError("Incident not found.")

        cursor = connection.execute(
            """
            INSERT INTO incident_actions (
                incident_id, action_type, description, action_status,
                performed_by, updated_by, updated_at
            )
            VALUES (?, ?, ?, 'proposed', ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                incident_id,
                normalized_type,
                safe_description,
                performed_by,
                performed_by,
            ),
        )
        action_id = cursor.lastrowid
        _record_timeline(
            connection,
            incident_id,
            "Response recommendation recorded",
            f"Action record {action_id} was recorded as a {normalized_type.lower()}.",
        )
        _record_audit(
            connection,
            performed_by,
            "INCIDENT_ACTION_CREATED",
            f"Action record {action_id} added to {incident['incident_reference']}.",
        )
        connection.commit()
    return action_id


def get_incident_actions(incident_id):
    if type(incident_id) is not int or incident_id <= 0:
        return []
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT a.*, u.username AS recorded_by_username
            FROM incident_actions a
            LEFT JOIN users u ON u.id = a.performed_by
            WHERE a.incident_id = ?
            ORDER BY a.created_at, a.id
            """,
            (incident_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def update_incident_action_status(action_id, new_status, updated_by=None):
    if type(action_id) is not int or action_id <= 0:
        raise ValueError("Invalid response action ID.")
    if not isinstance(new_status, str):
        raise ValueError("Invalid response action status.")
    normalized_status = new_status.strip().lower()
    if normalized_status not in ALLOWED_ACTION_STATUSES:
        raise ValueError("Invalid response action status.")

    with get_db_connection() as connection:
        if type(updated_by) is not int or updated_by <= 0:
            raise ValueError("An active user is required to update a response action.")
        _validate_actor(connection, updated_by)
        action = connection.execute(
            """
            SELECT a.id, a.incident_id, a.action_type, a.action_status,
                   i.incident_reference
            FROM incident_actions a
            JOIN incidents i ON i.id = a.incident_id
            WHERE a.id = ?
            """,
            (action_id,),
        ).fetchone()
        if action is None:
            raise ValueError("Response action not found.")
        actor_role = _require_actor_role(
            connection,
            updated_by,
            {"admin", "analyst"},
            "Only active administrators and analysts may update response actions.",
        )
        current_status = action["action_status"]
        if current_status == normalized_status:
            return False
        if actor_role == "analyst" and (
            action["action_type"] != "RECOMMENDATION"
            or current_status != "approved"
            or normalized_status != "in_progress"
        ):
            raise ValueError(
                "Analysts may only move approved recommendations to in progress."
            )
        if normalized_status not in ACTION_STATUS_TRANSITIONS.get(current_status, set()):
            raise ValueError(
                f"Response action cannot transition from {current_status} to {normalized_status}."
            )

        connection.execute(
            """
            UPDATE incident_actions
            SET action_status = ?,
                updated_by = ?,
                updated_at = CURRENT_TIMESTAMP,
                completed_at = CASE
                    WHEN ? = 1 THEN CURRENT_TIMESTAMP
                    ELSE NULL
                END
            WHERE id = ?
            """,
            (
                normalized_status,
                updated_by,
                int(normalized_status == "completed"),
                action_id,
            ),
        )
        details = (
            f"Action record {action_id}: {current_status} -> {normalized_status}."
        )
        _record_timeline(
            connection,
            action["incident_id"],
            "Response recommendation status changed",
            details,
        )
        _record_audit(
            connection,
            updated_by,
            "INCIDENT_ACTION_STATUS_UPDATED",
            f"{action['incident_reference']}: {details}",
        )
        connection.commit()
    return True
