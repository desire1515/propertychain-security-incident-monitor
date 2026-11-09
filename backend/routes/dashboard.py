from flask import Blueprint, render_template

from backend.utils.security import login_required
from database.db import get_db_connection

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    with get_db_connection() as connection:
        stats = {
            "total_events": connection.execute(
                "SELECT COUNT(*) FROM security_events"
            ).fetchone()[0],
            "total_incidents": connection.execute(
                "SELECT COUNT(*) FROM incidents"
            ).fetchone()[0],
            "open_incidents": connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'open'"
            ).fetchone()[0],
            "investigating_incidents": connection.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = 'investigating'"
            ).fetchone()[0],
            "critical_incidents": connection.execute(
                """
                SELECT COUNT(*) FROM incidents
                WHERE severity = 'critical'
                AND status != 'closed'
                """
            ).fetchone()[0],
            "active_sources": connection.execute(
                """
                SELECT COUNT(*)
                FROM monitoring_sources
                WHERE monitoring_mode = 'REAL'
                  AND connection_status IN ('CONNECTED', 'DEGRADED')
                  AND is_enabled = 1
                  AND last_successful_check IS NOT NULL
                """
            ).fetchone()[0]
        }

        for classification in ("REAL", "SIMULATED", "TEST"):
            stats[f"{classification.lower()}_events"] = connection.execute(
                "SELECT COUNT(*) FROM security_events WHERE classification = ?",
                (classification,),
            ).fetchone()[0]

        incident_severity_distribution = connection.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM incidents
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                ELSE 4
            END
            """
        ).fetchall()

        event_classification_distribution = connection.execute(
            """
            SELECT classification, COUNT(*) AS count
            FROM security_events
            GROUP BY classification
            ORDER BY classification
            """
        ).fetchall()

        recent_events = connection.execute(
            """
            SELECT event_reference, event_type, source, severity, classification,
                   received_at
            FROM security_events
            ORDER BY received_at DESC, id DESC
            LIMIT 5
            """
        ).fetchall()

        recent_incidents = connection.execute(
            """
            SELECT incident_reference, title, severity, status, created_at
            FROM incidents
            ORDER BY created_at DESC, id DESC
            LIMIT 5
            """
        ).fetchall()

        source_health = connection.execute(
            """
            SELECT source_name, monitoring_mode, connection_status, is_enabled,
                   last_checked_at, last_successful_check
            FROM monitoring_sources
            ORDER BY source_name COLLATE NOCASE
            """
        ).fetchall()

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_events=recent_events,
        recent_incidents=recent_incidents,
        incident_severity_distribution=incident_severity_distribution,
        event_classification_distribution=event_classification_distribution,
        source_health=source_health,
    )
