import re
import sqlite3
from datetime import datetime, timezone

from database.db import get_db_connection

ALLOWED_SOURCE_TYPES = {
    "FIREBASE",
    "BLOCKCHAIN",
    "APPLICATION",
    "SIMULATION",
    "OTHER",
}
ALLOWED_MONITORING_MODES = {"REAL", "SIMULATED", "PLANNED"}
ALLOWED_CONNECTION_STATUSES = {
    "NOT_CONNECTED",
    "CONNECTED",
    "DEGRADED",
    "ERROR",
    "DISABLED",
}


def _normalize_name(value):
    if not isinstance(value, str):
        raise ValueError("Source name is required.")

    normalized = value.strip()
    if not normalized:
        raise ValueError("Source name is required.")

    if len(normalized) > 200:
        raise ValueError("Source name cannot exceed 200 characters.")

    return normalized


def _normalize_upper(value, field_name, allowed_values):
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"Invalid {field_name}.")

    normalized = value.strip().upper()
    if normalized not in allowed_values:
        raise ValueError(f"Invalid {field_name}.")

    return normalized


def _normalize_description(value):
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("Description must be a string.")

    description = value.strip()
    if description and len(description) > 2000:
        raise ValueError("Description cannot exceed 2000 characters.")

    return description or None


def _sanitize_audit_value(value):
    if value is None:
        return None

    if not isinstance(value, str):
        value = str(value)

    sanitized = value.strip()
    if not sanitized:
        return None

    redactions = [
        (
            r"(?is)(api[_-]?key|firebase[_-]?credential|private[_-]?key|wallet[_-]?secret|secret|token|authorization|bearer)\s*[:=]\s*([^,\s;]+)",
            "[REDACTED]",
        ),
        (r"(?is)(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)", "[REDACTED]"),
        (r"(?is)(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", "[REDACTED]"),
        (r"(?is)(secret\s+token\s+[A-Za-z0-9._~+/=-]+)", "[REDACTED]"),
        (r"(?is)(token\s*[:=]?\s*[A-Za-z0-9._~+/=-]{3,})", "[REDACTED]"),
        (r"(?is)(secret\s*[:=]?\s*[A-Za-z0-9._~+/=-]{3,})", "[REDACTED]"),
        (r"(?is)(password\s*[:=]?\s*[A-Za-z0-9._~+/=-]{3,})", "[REDACTED]"),
    ]

    for pattern, replacement in redactions:
        sanitized = re.sub(pattern, replacement, sanitized)

    sanitized = re.sub(r"(?i)(password|secret|token|key)\s*[:=]\s*[A-Za-z0-9._~+/=-]+", "[REDACTED]", sanitized)
    sanitized = " ".join(sanitized.split())

    if len(sanitized) > 500:
        sanitized = sanitized[:500]

    return sanitized or None


def _safe_user_exists(connection, user_id):
    if user_id is None:
        return True

    if not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("Invalid user identifier.")

    user = connection.execute(
        "SELECT id FROM users WHERE id = ? AND is_active = 1",
        (user_id,),
    ).fetchone()

    if user is None:
        raise ValueError("Acting user does not exist or is inactive.")

    return True


def _compute_status_from_state(is_enabled, connection_status, monitoring_mode):
    if not bool(is_enabled):
        return "inactive"
    if monitoring_mode == "PLANNED":
        return "inactive"
    if connection_status in {"CONNECTED", "DEGRADED"}:
        return "active"
    return "inactive"


def _record_audit(connection, user_id, action, details):
    audit_details = _sanitize_audit_value(details)
    if not audit_details:
        return

    connection.execute(
        """
        INSERT INTO system_audit_logs (user_id, action, details)
        VALUES (?, ?, ?)
        """,
        (user_id, action, audit_details),
    )


def _check_name_uniqueness(connection, source_name, source_id=None):
    normalized = source_name.strip().lower()
    row = connection.execute(
        """
        SELECT id
        FROM monitoring_sources
        WHERE LOWER(TRIM(source_name)) = ?
        """,
        (normalized,),
    ).fetchone()

    if row and (source_id is None or row["id"] != source_id):
        raise ValueError("A monitoring source with this name already exists.")


def _validate_monitoring_source_state(is_enabled, monitoring_mode, connection_status):
    if monitoring_mode not in ALLOWED_MONITORING_MODES:
        raise ValueError("Invalid monitoring mode.")
    if connection_status not in ALLOWED_CONNECTION_STATUSES:
        raise ValueError("Invalid connection status.")

    if connection_status == "DISABLED" and bool(is_enabled):
        raise ValueError("Disabled sources must not be reported as enabled.")

    if connection_status in {"CONNECTED", "DEGRADED"} and not bool(is_enabled):
        raise ValueError("Disabled sources must not be reported as actively connected.")

    if monitoring_mode == "PLANNED" and connection_status == "CONNECTED" and bool(is_enabled):
        raise ValueError("A planned source must not be marked CONNECTED.")

    if monitoring_mode in {"PLANNED", "SIMULATED"} and connection_status == "CONNECTED" and bool(is_enabled):
        raise ValueError("Only verified real sources may be marked CONNECTED.")

    if monitoring_mode == "PLANNED" and bool(is_enabled):
        raise ValueError("Planned monitoring sources cannot be enabled without a verified connection.")

    if connection_status == "NOT_CONNECTED" and bool(is_enabled):
        raise ValueError("A not-connected source cannot be enabled.")

    if connection_status == "DEGRADED" and monitoring_mode in {"PLANNED", "SIMULATED"}:
        raise ValueError("Only verified real sources may be marked DEGRADED.")


def _ensure_source_connection_is_valid(source, candidate_status=None, candidate_enabled=None):
    if candidate_status is None:
        candidate_status = source.get("connection_status")
    if candidate_enabled is None:
        candidate_enabled = bool(source.get("is_enabled"))

    if candidate_status in {"CONNECTED", "DEGRADED"}:
        if source.get("monitoring_mode") in {"PLANNED", "SIMULATED"}:
            raise ValueError("Only verified real sources may be marked CONNECTED or DEGRADED.")
        if source.get("last_successful_check") is None:
            raise ValueError("A source must have a successful verified integration check before it can be marked CONNECTED or DEGRADED.")

    if candidate_status == "DISABLED":
        candidate_enabled = False

    if candidate_status in {"CONNECTED", "DEGRADED"} and not bool(candidate_enabled):
        raise ValueError("Disabled sources must not be reported as actively connected.")


def create_monitoring_source(
    source_name,
    source_type,
    monitoring_mode="PLANNED",
    description=None,
    connection_status=None,
    is_enabled=False,
    created_by=None,
):
    normalized_name = _normalize_name(source_name)
    normalized_type = _normalize_upper(source_type, "source type", ALLOWED_SOURCE_TYPES)
    normalized_mode = _normalize_upper(
        monitoring_mode,
        "monitoring mode",
        ALLOWED_MONITORING_MODES,
    )
    normalized_description = _normalize_description(description)
    normalized_status = _normalize_upper(
        connection_status,
        "connection status",
        ALLOWED_CONNECTION_STATUSES,
    )

    if normalized_mode is None:
        normalized_mode = "PLANNED"
    if normalized_status is None:
        normalized_status = "NOT_CONNECTED"
    if not isinstance(is_enabled, bool):
        raise ValueError("Enabled flag must be a boolean.")

    if normalized_status in {"CONNECTED", "DEGRADED"}:
        if not is_enabled:
            raise ValueError("Disabled sources must not be reported as actively connected.")
        if normalized_mode == "PLANNED":
            raise ValueError("A planned source must not be marked CONNECTED.")
        if normalized_mode == "SIMULATED":
            raise ValueError("Only verified real sources may be marked CONNECTED or DEGRADED.")
        raise ValueError("Monitoring sources must not be marked CONNECTED or DEGRADED without a verified real integration health check.")

    if normalized_status == "DISABLED":
        is_enabled = False

    _validate_monitoring_source_state(is_enabled, normalized_mode, normalized_status)
    status_value = _compute_status_from_state(is_enabled, normalized_status, normalized_mode)

    try:
        with get_db_connection() as connection:
            _safe_user_exists(connection, created_by)
            _check_name_uniqueness(connection, normalized_name)

            cursor = connection.execute(
                """
                INSERT INTO monitoring_sources (
                    source_name,
                    source_type,
                    status,
                    description,
                    monitoring_mode,
                    connection_status,
                    is_enabled,
                    last_checked_at,
                    last_successful_check,
                    last_error,
                    created_by,
                    updated_by,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    normalized_name,
                    normalized_type,
                    status_value,
                    normalized_description,
                    normalized_mode,
                    normalized_status,
                    int(is_enabled),
                    None,
                    None,
                    None,
                    created_by,
                    created_by,
                ),
            )
            source_id = cursor.lastrowid
            _record_audit(
                connection,
                created_by,
                "MONITORING_SOURCE_CREATED",
                f"Monitoring source created: {normalized_name}",
            )
            connection.commit()

        return source_id

    except sqlite3.IntegrityError as exc:
        raise ValueError("Monitoring source could not be created because of a database constraint.") from exc


def get_monitoring_sources(
    source_type=None,
    monitoring_mode=None,
    connection_status=None,
    is_enabled=None,
    search_query=None,
):
    clauses = []
    params = []

    if source_type is not None:
        normalized_type = _normalize_upper(source_type, "source type", ALLOWED_SOURCE_TYPES)
        clauses.append("source_type = ?")
        params.append(normalized_type)

    if monitoring_mode is not None:
        normalized_mode = _normalize_upper(
            monitoring_mode,
            "monitoring mode",
            ALLOWED_MONITORING_MODES,
        )
        clauses.append("monitoring_mode = ?")
        params.append(normalized_mode)

    if connection_status is not None:
        normalized_status = _normalize_upper(
            connection_status,
            "connection status",
            ALLOWED_CONNECTION_STATUSES,
        )
        clauses.append("connection_status = ?")
        params.append(normalized_status)

    if is_enabled is not None:
        if not isinstance(is_enabled, bool):
            raise ValueError("Enabled filter must be a boolean.")
        clauses.append("is_enabled = ?")
        params.append(int(is_enabled))

    if search_query is not None:
        search_value = (search_query or "").strip()
        if search_value:
            clauses.append(
                "(LOWER(source_name) LIKE ? OR LOWER(COALESCE(description, '')) LIKE ?)"
            )
            params.extend([f"%{search_value.lower()}%", f"%{search_value.lower()}%"])

    sql = """
        SELECT *
        FROM monitoring_sources
    """
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)

    sql += " ORDER BY created_at DESC, id DESC"

    with get_db_connection() as connection:
        rows = connection.execute(sql, tuple(params)).fetchall()

    return [dict(row) for row in rows]


def get_monitoring_source_by_id(source_id):
    if not isinstance(source_id, int) or source_id <= 0:
        return None

    with get_db_connection() as connection:
        source = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()

    return dict(source) if source else None


def update_monitoring_source(
    source_id,
    source_name=None,
    source_type=None,
    monitoring_mode=None,
    description=None,
    connection_status=None,
    is_enabled=None,
    updated_by=None,
):
    if not isinstance(source_id, int) or source_id <= 0:
        raise ValueError("Invalid monitoring source ID.")

    with get_db_connection() as connection:
        source = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()

        if source is None:
            raise ValueError("Invalid monitoring source ID.")

        _safe_user_exists(connection, updated_by)

        values = {
            "source_name": source["source_name"],
            "source_type": source["source_type"],
            "monitoring_mode": source["monitoring_mode"],
            "description": source["description"],
            "connection_status": source["connection_status"],
            "is_enabled": bool(source["is_enabled"]),
        }

        if source_name is not None:
            values["source_name"] = _normalize_name(source_name)
        if source_type is not None:
            values["source_type"] = _normalize_upper(
                source_type,
                "source type",
                ALLOWED_SOURCE_TYPES,
            )
        if monitoring_mode is not None:
            values["monitoring_mode"] = _normalize_upper(
                monitoring_mode,
                "monitoring mode",
                ALLOWED_MONITORING_MODES,
            )
        if description is not None:
            values["description"] = _normalize_description(description)
        if connection_status is not None:
            values["connection_status"] = _normalize_upper(
                connection_status,
                "connection status",
                ALLOWED_CONNECTION_STATUSES,
            )
        if is_enabled is not None:
            if not isinstance(is_enabled, bool):
                raise ValueError("Enabled flag must be a boolean.")
            values["is_enabled"] = is_enabled

        if values["connection_status"] == "DISABLED":
            values["is_enabled"] = False

        _validate_monitoring_source_state(
            values["is_enabled"],
            values["monitoring_mode"],
            values["connection_status"],
        )

        if values["connection_status"] in {"CONNECTED", "DEGRADED"}:
            _ensure_source_connection_is_valid(
                {
                    **dict(source),
                    "monitoring_mode": values["monitoring_mode"],
                    "connection_status": values["connection_status"],
                    "is_enabled": int(values["is_enabled"]),
                    "last_successful_check": source["last_successful_check"] if "last_successful_check" in source.keys() else None,
                },
                values["connection_status"],
                values["is_enabled"],
            )

        source_name_changed = values["source_name"] != source["source_name"]
        if source_name_changed:
            _check_name_uniqueness(connection, values["source_name"], source_id)

        final_status = _compute_status_from_state(
            values["is_enabled"],
            values["connection_status"],
            values["monitoring_mode"],
        )

        if (
            source["source_name"] == values["source_name"]
            and source["source_type"] == values["source_type"]
            and (source["description"] or None) == (values["description"] or None)
            and source["monitoring_mode"] == values["monitoring_mode"]
            and source["connection_status"] == values["connection_status"]
            and bool(source["is_enabled"]) == values["is_enabled"]
        ):
            return False

        connection.execute(
            """
            UPDATE monitoring_sources
            SET source_name = ?,
                source_type = ?,
                description = ?,
                monitoring_mode = ?,
                connection_status = ?,
                is_enabled = ?,
                status = ?,
                updated_by = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                values["source_name"],
                values["source_type"],
                values["description"],
                values["monitoring_mode"],
                values["connection_status"],
                int(values["is_enabled"]),
                final_status,
                updated_by,
                source_id,
            ),
        )

        _record_audit(
            connection,
            updated_by,
            "MONITORING_SOURCE_UPDATED",
            f"Monitoring source updated: {values['source_name']}",
        )
        connection.commit()

    return True


def update_monitoring_source_status(source_id, status, updated_by=None):
    if not isinstance(source_id, int) or source_id <= 0:
        raise ValueError("Invalid monitoring source ID.")

    if not isinstance(status, str):
        raise ValueError("Invalid monitoring source status.")

    normalized_status = status.strip().upper()
    if normalized_status not in ALLOWED_CONNECTION_STATUSES | {"ACTIVE", "INACTIVE"}:
        raise ValueError("Invalid monitoring source status.")

    with get_db_connection() as connection:
        _safe_user_exists(connection, updated_by)
        row = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()
        if row is None:
            raise ValueError("Monitoring source not found.")

        current = dict(row)

        if normalized_status == "ACTIVE":
            next_status = "CONNECTED"
            next_enabled = 1
        elif normalized_status == "INACTIVE":
            next_status = (
                "DISABLED"
                if not bool(current["is_enabled"])
                else "NOT_CONNECTED"
            )
            next_enabled = 0
        elif normalized_status in {"DISABLED", "NOT_CONNECTED"}:
            next_enabled = 0
            next_status = normalized_status
        elif normalized_status == "CONNECTED":
            next_enabled = 1
            next_status = "CONNECTED"
        elif normalized_status == "DEGRADED":
            if not bool(current["is_enabled"]):
                raise ValueError("Disabled sources must not be reported as DEGRADED.")
            next_enabled = 1
            next_status = "DEGRADED"
        else:
            next_enabled = 1 if bool(current["is_enabled"]) else 0
            next_status = normalized_status

        _validate_monitoring_source_state(next_enabled, current["monitoring_mode"], next_status)
        if next_status in {"CONNECTED", "DEGRADED"}:
            _ensure_source_connection_is_valid(
                current,
                candidate_status=next_status,
                candidate_enabled=next_enabled,
            )

        if current["connection_status"] == next_status and bool(current["is_enabled"]) == bool(next_enabled):
            return False

        connection.execute(
            """
            UPDATE monitoring_sources
            SET connection_status = ?,
                is_enabled = ?,
                status = ?,
                updated_by = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                next_status,
                int(next_enabled),
                _compute_status_from_state(
                    next_enabled,
                    next_status,
                    current["monitoring_mode"],
                ),
                updated_by,
                source_id,
            ),
        )
        _record_audit(
            connection,
            updated_by,
            "MONITORING_SOURCE_STATUS_CHANGED",
            f"Status updated for {current['source_name']}: {current['connection_status']} -> {next_status}",
        )
        connection.commit()

    return True


def delete_monitoring_source(source_id, deleted_by=None):
    if not isinstance(source_id, int) or source_id <= 0:
        raise ValueError("Invalid monitoring source ID.")

    with get_db_connection() as connection:
        source = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()

        if source is None:
            raise ValueError("Monitoring source not found.")

        connection.execute(
            """
            UPDATE monitoring_sources
            SET is_enabled = 0,
                connection_status = 'DISABLED',
                status = 'inactive',
                updated_by = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (deleted_by, source_id),
        )
        _record_audit(
            connection,
            deleted_by,
            "MONITORING_SOURCE_DISABLED",
            f"Monitoring source disabled instead of deleted: {source['source_name']}",
        )
        connection.commit()

    return True


def record_monitoring_check(source_id, success, error=None, checked_by=None):
    if not isinstance(source_id, int) or source_id <= 0:
        raise ValueError("Invalid monitoring source ID.")

    if not isinstance(success, bool):
        raise ValueError("Check result must be a boolean.")

    if not isinstance(checked_by, int) or checked_by <= 0:
        raise ValueError("An active administrator is required to record a monitoring check.")

    if error is not None and not isinstance(error, str):
        raise ValueError("Error details must be a string.")

    with get_db_connection() as connection:
        source = connection.execute(
            "SELECT * FROM monitoring_sources WHERE id = ?",
            (source_id,),
        ).fetchone()

        if source is None:
            raise ValueError("Monitoring source not found.")

        administrator = connection.execute(
            "SELECT id FROM users WHERE id = ? AND is_active = 1 AND role = 'admin'",
            (checked_by,),
        ).fetchone()
        if administrator is None:
            raise ValueError("An active administrator is required to record a monitoring check.")

        if error is not None:
            error_text = _sanitize_audit_value(error)
        else:
            error_text = None

        now = datetime.now(timezone.utc).isoformat()
        last_error = source["last_error"] if success else (
            error_text or "Manual administrative check reported failure."
        )
        audit_message = (
            f"Manual administrative check reported {'success' if success else 'failure'} "
            f"for {source['source_name']}; no external health check was performed."
        )
        if not success and error_text:
            audit_message += f" Details: {error_text}"

        connection.execute(
            """
            UPDATE monitoring_sources
            SET last_checked_at = ?,
                last_error = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (now, last_error, source_id),
        )
        _record_audit(
            connection,
            checked_by,
            "MONITORING_SOURCE_CHECKED",
            audit_message,
        )
        connection.commit()

    return get_monitoring_source_by_id(source_id)


def ensure_default_monitoring_sources():
    defaults = [
        {
            "source_name": "PropertyChain Firebase",
            "source_type": "FIREBASE",
            "monitoring_mode": "PLANNED",
            "connection_status": "NOT_CONNECTED",
            "is_enabled": False,
            "description": "Planned connection to the PropertyChain Firebase integration.",
        },
        {
            "source_name": "Ethereum Sepolia Smart Contracts",
            "source_type": "BLOCKCHAIN",
            "monitoring_mode": "PLANNED",
            "connection_status": "NOT_CONNECTED",
            "is_enabled": False,
            "description": "Planned blockchain monitoring for Sepolia contracts.",
        },
        {
            "source_name": "PCSIRM Application",
            "source_type": "APPLICATION",
            "monitoring_mode": "SIMULATED",
            "connection_status": "NOT_CONNECTED",
            "is_enabled": False,
            "description": "Simulated internal application monitoring source.",
        },
        {
            "source_name": "PCSIRM Simulation Engine",
            "source_type": "SIMULATION",
            "monitoring_mode": "SIMULATED",
            "connection_status": "NOT_CONNECTED",
            "is_enabled": False,
            "description": "Simulated monitoring source used for controlled event generation.",
        },
    ]

    with get_db_connection() as connection:
        for source in defaults:
            normalized_name = _normalize_name(source["source_name"])
            existing = connection.execute(
                "SELECT * FROM monitoring_sources WHERE LOWER(TRIM(source_name)) = ?",
                (normalized_name.lower(),),
            ).fetchone()

            if existing is not None:
                continue

            connection.execute(
                """
                INSERT INTO monitoring_sources (
                    source_name,
                    source_type,
                    status,
                    description,
                    monitoring_mode,
                    connection_status,
                    is_enabled,
                    last_checked_at,
                    last_successful_check,
                    last_error,
                    created_by,
                    updated_by,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (
                    normalized_name,
                    source["source_type"],
                    "inactive",
                    source["description"],
                    source["monitoring_mode"],
                    source["connection_status"],
                    int(bool(source["is_enabled"])),
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            )
        connection.commit()
