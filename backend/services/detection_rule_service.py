import re

from database.db import get_db_connection

ALLOWED_RULE_SEVERITIES = {"low", "medium", "high", "critical"}
MAX_RULE_WINDOW_MINUTES = 10080
ALLOWED_ALERT_STATUSES = {"open", "acknowledged", "investigating", "resolved"}
ALERT_STATUS_TRANSITIONS = {
    "open": {"acknowledged", "resolved"},
    "acknowledged": {"investigating", "resolved"},
    "investigating": {"resolved"},
    "resolved": {"open"},
}
DEFAULT_DETECTION_RULES = (
    ("Repeated failed login attempts", "AUTHENTICATION_FAILED", "high", 5, 10),
    ("Suspicious authentication activity", "SUSPICIOUS_AUTH_ACTIVITY", "high", 1, 60),
    ("Unauthorized role changes", "UNAUTHORIZED_ROLE_CHANGE", "critical", 1, 60),
    ("Suspicious property modifications", "SUSPICIOUS_PROPERTY_MODIFICATION", "high", 1, 60),
    ("Unusual document uploads", "UNUSUAL_DOCUMENT_UPLOAD", "medium", 1, 60),
    ("Repeated access denied events", "ACCESS_DENIED", "medium", 5, 10),
    ("Suspicious smart-contract activity", "SUSPICIOUS_CONTRACT_ACTIVITY", "critical", 1, 60),
    ("Multiple events from one source", "*", "high", 10, 10),
    ("Unexpected application errors", "APPLICATION_ERROR", "high", 1, 60),
)


def _validate_rule(
    rule_name,
    event_type,
    severity,
    threshold,
    window_minutes,
    description,
):
    if not isinstance(rule_name, str) or not rule_name.strip():
        raise ValueError("Rule name is required.")
    normalized_name = rule_name.strip()
    if len(normalized_name) > 120:
        raise ValueError("Rule name cannot exceed 120 characters.")

    if not isinstance(event_type, str):
        raise ValueError("Invalid rule event type.")
    normalized_event_type = event_type.strip().upper()
    if normalized_event_type != "*" and not re.fullmatch(
        r"[A-Z][A-Z0-9_]{0,99}",
        normalized_event_type,
    ):
        raise ValueError("Invalid rule event type.")

    if not isinstance(severity, str):
        raise ValueError("Invalid rule severity.")
    normalized_severity = severity.strip().lower()
    if normalized_severity not in ALLOWED_RULE_SEVERITIES:
        raise ValueError("Invalid rule severity.")

    if type(threshold) is not int or not 1 <= threshold <= 10000:
        raise ValueError("Rule threshold must be between 1 and 10000.")
    if (
        type(window_minutes) is not int
        or not 1 <= window_minutes <= MAX_RULE_WINDOW_MINUTES
    ):
        raise ValueError("Rule window must be between 1 and 10080 minutes.")

    if description is not None and not isinstance(description, str):
        raise ValueError("Rule description must be a string.")
    normalized_description = description.strip() if description else None
    if normalized_description and len(normalized_description) > 2000:
        raise ValueError("Rule description cannot exceed 2000 characters.")

    return (
        normalized_name,
        normalized_event_type,
        normalized_severity,
        threshold,
        window_minutes,
        normalized_description or None,
    )


def _require_admin(connection, user_id):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("An active administrator is required.")
    user = connection.execute(
        "SELECT id FROM users WHERE id = ? AND is_active = 1 AND role = 'admin'",
        (user_id,),
    ).fetchone()
    if user is None:
        raise ValueError("An active administrator is required.")


def _record_rule_audit(connection, user_id, action, rule_id):
    connection.execute(
        """
        INSERT INTO system_audit_logs (user_id, action, details)
        VALUES (?, ?, ?)
        """,
        (user_id, action, f"Detection rule ID {rule_id}."),
    )


def _ensure_rule_name_unique(connection, rule_name, rule_id=None):
    duplicate = connection.execute(
        """
        SELECT id FROM detection_rules
        WHERE LOWER(TRIM(rule_name)) = LOWER(TRIM(?))
        """,
        (rule_name,),
    ).fetchone()
    if duplicate is not None and duplicate["id"] != rule_id:
        raise ValueError("A detection rule with this name already exists.")


def create_detection_rule(
    rule_name,
    event_type,
    severity,
    threshold=1,
    window_minutes=60,
    description=None,
    created_by=None,
    is_enabled=True,
):
    values = _validate_rule(
        rule_name,
        event_type,
        severity,
        threshold,
        window_minutes,
        description,
    )
    if not isinstance(is_enabled, bool):
        raise ValueError("Enabled flag must be a boolean.")

    with get_db_connection() as connection:
        _require_admin(connection, created_by)
        _ensure_rule_name_unique(connection, values[0])
        cursor = connection.execute(
            """
            INSERT INTO detection_rules (
                rule_name, description, event_type, severity, is_enabled,
                threshold, window_minutes, created_by, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                values[0],
                values[5],
                values[1],
                values[2],
                int(is_enabled),
                values[3],
                values[4],
                created_by,
            ),
        )
        rule_id = cursor.lastrowid
        _record_rule_audit(
            connection,
            created_by,
            "DETECTION_RULE_CREATED",
            rule_id,
        )
        connection.commit()
    return rule_id


def get_detection_rules():
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM detection_rules
            ORDER BY rule_name COLLATE NOCASE, id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_detection_rule_by_id(rule_id):
    if type(rule_id) is not int or rule_id <= 0:
        return None
    with get_db_connection() as connection:
        row = connection.execute(
            "SELECT * FROM detection_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
    return dict(row) if row else None


def update_detection_rule(
    rule_id,
    rule_name,
    event_type,
    severity,
    threshold,
    window_minutes,
    description=None,
    updated_by=None,
):
    if type(rule_id) is not int or rule_id <= 0:
        raise ValueError("Invalid detection rule ID.")
    values = _validate_rule(
        rule_name,
        event_type,
        severity,
        threshold,
        window_minutes,
        description,
    )
    with get_db_connection() as connection:
        _require_admin(connection, updated_by)
        current = connection.execute(
            "SELECT * FROM detection_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        if current is None:
            raise ValueError("Detection rule not found.")
        _ensure_rule_name_unique(connection, values[0], rule_id=rule_id)

        old_values = (
            current["rule_name"],
            current["event_type"],
            current["severity"],
            current["threshold"],
            current["window_minutes"],
            current["description"],
        )
        if old_values == values:
            return False

        connection.execute(
            """
            UPDATE detection_rules
            SET rule_name = ?, event_type = ?, severity = ?, threshold = ?,
                window_minutes = ?, description = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (*values[:5], values[5], rule_id),
        )
        _record_rule_audit(
            connection,
            updated_by,
            "DETECTION_RULE_UPDATED",
            rule_id,
        )
        connection.commit()
    return True


def get_detection_alerts(status=None, limit=100):
    if status is not None and (
        not isinstance(status, str) or status not in ALLOWED_ALERT_STATUSES
    ):
        raise ValueError("Invalid alert status.")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")

    clauses = []
    params = []
    if status is not None:
        clauses.append("a.status = ?")
        params.append(status)

    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with get_db_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT a.*, r.rule_name, e.event_reference, e.event_type,
                   e.source, e.classification, i.incident_reference
            FROM detection_alerts a
            JOIN detection_rules r ON r.id = a.rule_id
            JOIN security_events e ON e.id = a.event_id
            LEFT JOIN incidents i ON i.source_event_id = e.id
            {where_clause}
            ORDER BY a.created_at DESC, a.id DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [dict(row) for row in rows]


def set_detection_alert_status(alert_id, status, updated_by):
    if type(alert_id) is not int or alert_id <= 0:
        raise ValueError("Invalid detection alert ID.")
    if not isinstance(status, str) or status not in ALLOWED_ALERT_STATUSES:
        raise ValueError("Invalid alert status.")

    with get_db_connection() as connection:
        _require_admin(connection, updated_by)
        alert = connection.execute(
            "SELECT id, status FROM detection_alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert is None:
            raise ValueError("Detection alert not found.")
        if alert["status"] == status:
            return False
        if status not in ALERT_STATUS_TRANSITIONS.get(alert["status"], set()):
            raise ValueError(
                f"Detection alert cannot transition from {alert['status']} to {status}."
            )

        connection.execute(
            "UPDATE detection_alerts SET status = ? WHERE id = ?",
            (status, alert_id),
        )
        connection.execute(
            """
            INSERT INTO detection_alert_history (
                alert_id, previous_status, new_status, changed_by
            )
            VALUES (?, ?, ?, ?)
            """,
            (alert_id, alert["status"], status, updated_by),
        )
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, 'DETECTION_ALERT_STATUS_CHANGED', ?)
            """,
            (
                updated_by,
                f"Detection alert ID {alert_id}: {alert['status']} -> {status}.",
            ),
        )
        connection.commit()
    return True


def get_detection_alert_history(alert_id):
    if type(alert_id) is not int or alert_id <= 0:
        return []
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT h.*, u.username AS changed_by_username
            FROM detection_alert_history h
            LEFT JOIN users u ON u.id = h.changed_by
            WHERE h.alert_id = ?
            ORDER BY h.changed_at, h.id
            """,
            (alert_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def set_detection_rule_enabled(rule_id, is_enabled, updated_by):
    if type(rule_id) is not int or rule_id <= 0:
        raise ValueError("Invalid detection rule ID.")
    if not isinstance(is_enabled, bool):
        raise ValueError("Enabled flag must be a boolean.")

    with get_db_connection() as connection:
        _require_admin(connection, updated_by)
        rule = connection.execute(
            "SELECT id, is_enabled FROM detection_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        if rule is None:
            raise ValueError("Detection rule not found.")
        if bool(rule["is_enabled"]) == is_enabled:
            return False

        connection.execute(
            """
            UPDATE detection_rules
            SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (int(is_enabled), rule_id),
        )
        _record_rule_audit(
            connection,
            updated_by,
            "DETECTION_RULE_ENABLED" if is_enabled else "DETECTION_RULE_DISABLED",
            rule_id,
        )
        connection.commit()
    return True


def ensure_default_detection_rules():
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for rule_name, event_type, severity, threshold, window_minutes in DEFAULT_DETECTION_RULES:
            exists = connection.execute(
                """
                SELECT id FROM detection_rules
                WHERE LOWER(TRIM(rule_name)) = LOWER(TRIM(?))
                """,
                (rule_name,),
            ).fetchone()
            if exists is not None:
                continue
            connection.execute(
                """
                INSERT INTO detection_rules (
                    rule_name, description, event_type, severity, is_enabled,
                    threshold, window_minutes, created_by, updated_at
                )
                VALUES (?, ?, ?, ?, 1, ?, ?, NULL, CURRENT_TIMESTAMP)
                """,
                (
                    rule_name,
                    "Default PCSIRM detection rule; thresholds are configurable.",
                    event_type,
                    severity,
                    threshold,
                    window_minutes,
                ),
            )
        connection.commit()


def evaluate_security_event(connection, event_id):
    event = connection.execute(
        "SELECT id, event_reference, event_type, source, received_at FROM security_events WHERE id = ?",
        (event_id,),
    ).fetchone()
    if event is None:
        raise ValueError("Security event not found.")

    rules = connection.execute(
        "SELECT * FROM detection_rules WHERE is_enabled = 1 ORDER BY id"
    ).fetchall()
    created_alerts = 0

    for rule in rules:
        matches_event_type = rule["event_type"] == "*" or (
            rule["event_type"] == event["event_type"]
        )
        matching_count = 0
        if matches_event_type:
            if rule["event_type"] == "*":
                count_row = connection.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM security_events
                    WHERE source = ?
                      AND datetime(received_at) >= datetime(?, ?)
                    """,
                    (
                        event["source"],
                        event["received_at"],
                        f"-{rule['window_minutes']} minutes",
                    ),
                ).fetchone()
            else:
                count_row = connection.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM security_events
                    WHERE event_type = ?
                      AND source = ?
                      AND datetime(received_at) >= datetime(?, ?)
                    """,
                    (
                        event["event_type"],
                        event["source"],
                        event["received_at"],
                        f"-{rule['window_minutes']} minutes",
                    ),
                ).fetchone()
            matching_count = count_row["count"]

        matched = matches_event_type and matching_count >= rule["threshold"]
        connection.execute(
            """
            INSERT INTO detection_rule_executions (
                rule_id, event_id, matched, matching_count
            )
            VALUES (?, ?, ?, ?)
            """,
            (rule["id"], event_id, int(matched), matching_count),
        )
        if not matched:
            continue

        duplicate = connection.execute(
            """
            SELECT a.id
            FROM detection_alerts a
            JOIN security_events prior_event ON prior_event.id = a.event_id
            WHERE a.rule_id = ?
              AND a.status = 'open'
              AND prior_event.source = ?
              AND datetime(a.created_at) >= datetime(?, ?)
            LIMIT 1
            """,
            (
                rule["id"],
                event["source"],
                event["received_at"],
                f"-{rule['window_minutes']} minutes",
            ),
        ).fetchone()
        if duplicate is not None:
            continue

        summary = (
            f"Rule {rule['id']} detected matching activity for "
            f"event {event['event_reference']}."
        )
        alert_cursor = connection.execute(
            """
            INSERT INTO detection_alerts (
                rule_id, event_id, severity, summary
            )
            VALUES (?, ?, ?, ?)
            """,
            (rule["id"], event_id, rule["severity"], summary),
        )
        connection.execute(
            """
            INSERT INTO detection_alert_history (
                alert_id, previous_status, new_status, changed_by
            )
            VALUES (?, NULL, 'open', NULL)
            """,
            (alert_cursor.lastrowid,),
        )
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (NULL, 'DETECTION_ALERT_CREATED', ?)
            """,
            (f"Detection alert created for event {event['event_reference']}.",),
        )
        created_alerts += 1

    return created_alerts
