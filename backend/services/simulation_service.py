from database.db import get_db_connection
from backend.services.event_service import record_security_event_in_connection

SIMULATION_SCENARIOS = {
    "brute_force_login": {
        "name": "Brute-force login attempt",
        "description": "Five controlled failed-login events for detection-rule validation.",
        "events": (
            ("AUTHENTICATION_FAILED", "high", "A simulated login attempt was rejected."),
        ) * 5,
    },
    "suspicious_admin_login": {
        "name": "Suspicious administrator login",
        "description": "A simulated suspicious administrator authentication event.",
        "events": (
            ("SUSPICIOUS_AUTH_ACTIVITY", "high", "A simulated administrator login was flagged."),
        ),
    },
    "unauthorized_role_change": {
        "name": "Unauthorized role modification",
        "description": "A simulated unauthorized role-change event.",
        "events": (
            ("UNAUTHORIZED_ROLE_CHANGE", "critical", "A simulated role change was rejected."),
        ),
    },
    "suspicious_property_change": {
        "name": "Suspicious property modification",
        "description": "A simulated suspicious property-change event.",
        "events": (
            ("SUSPICIOUS_PROPERTY_MODIFICATION", "high", "A simulated property modification was flagged."),
        ),
    },
    "unauthorized_document_access": {
        "name": "Unauthorized document access",
        "description": "A simulated access-denied event for a protected document.",
        "events": (
            ("ACCESS_DENIED", "medium", "A simulated protected-document request was denied."),
        ),
    },
    "suspicious_file_upload": {
        "name": "Suspicious file upload",
        "description": "A simulated unusual document-upload event.",
        "events": (
            ("UNUSUAL_DOCUMENT_UPLOAD", "medium", "A simulated file upload was flagged for review."),
        ),
    },
    "smart_contract_anomaly": {
        "name": "Smart-contract anomaly",
        "description": "A simulated smart-contract anomaly; no RPC or contract is contacted.",
        "events": (
            ("SUSPICIOUS_CONTRACT_ACTIVITY", "critical", "A simulated contract event was flagged."),
        ),
    },
    "repeated_failed_requests": {
        "name": "Repeated failed requests",
        "description": "Five controlled access-denied events from one simulated source.",
        "events": (
            ("ACCESS_DENIED", "medium", "A simulated request was denied."),
        ) * 5,
    },
    "application_service_failure": {
        "name": "Application service failure",
        "description": "A simulated application service-error event.",
        "events": (
            ("APPLICATION_ERROR", "high", "A simulated application service error was recorded."),
        ),
    },
}


def _require_admin(connection, user_id):
    if type(user_id) is not int or user_id <= 0:
        raise ValueError("An active administrator is required to run simulations.")
    user = connection.execute(
        "SELECT id FROM users WHERE id = ? AND is_active = 1 AND role = 'admin'",
        (user_id,),
    ).fetchone()
    if user is None:
        raise ValueError("An active administrator is required to run simulations.")


def run_simulation(scenario_key, executed_by):
    if not isinstance(scenario_key, str) or scenario_key not in SIMULATION_SCENARIOS:
        raise ValueError("Invalid simulation scenario.")

    scenario = SIMULATION_SCENARIOS[scenario_key]
    with get_db_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _require_admin(connection, executed_by)
        cursor = connection.execute(
            """
            INSERT INTO simulation_runs (
                scenario_name, description, status, events_generated, executed_by
            )
            VALUES (?, ?, 'running', 0, ?)
            """,
            (scenario["name"], scenario["description"], executed_by),
        )
        run_id = cursor.lastrowid
        references = []

        for event_type, severity, description in scenario["events"]:
            references.append(
                record_security_event_in_connection(
                    connection,
                    source=f"PCSIRM Simulation / {scenario['name']}",
                    event_type=event_type,
                    severity=severity,
                    classification="SIMULATED",
                    description=description,
                    raw_data={
                        "simulation_run_id": run_id,
                        "scenario": scenario_key,
                    },
                )
            )

        connection.execute(
            """
            UPDATE simulation_runs
            SET status = 'completed',
                events_generated = ?,
                completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (len(references), run_id),
        )
        connection.execute(
            """
            INSERT INTO system_audit_logs (user_id, action, details)
            VALUES (?, 'SIMULATION_EXECUTED', ?)
            """,
            (
                executed_by,
                f"Simulation run ID {run_id} generated {len(references)} events.",
            ),
        )
        connection.commit()

    return {
        "id": run_id,
        "scenario_name": scenario["name"],
        "events_generated": len(references),
        "event_references": references,
    }


def get_simulation_runs(limit=50):
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT s.*, u.username AS executed_by_username
            FROM simulation_runs s
            LEFT JOIN users u ON u.id = s.executed_by
            ORDER BY s.started_at DESC, s.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
