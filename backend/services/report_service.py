from datetime import date
import json

from backend.utils.security import redact_sensitive_text
from database.db import get_db_connection

REPORT_CATEGORIES = {
    "events",
    "incidents",
    "detection",
    "monitoring",
    "simulations",
    "ingestion",
    "actions",
    "evidence",
    "audit",
}
SEVERITIES = {"low", "medium", "high", "critical"}
CLASSIFICATIONS = {"REAL", "SIMULATED", "TEST"}
INCIDENT_STATUSES = {
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed",
}


def validate_report_filters(
    start_date=None,
    end_date=None,
    severity=None,
    classification=None,
    incident_status=None,
    record_status=None,
    source=None,
    category=None,
):
    normalized = {}
    for key, value in (("start_date", start_date), ("end_date", end_date)):
        if value in (None, ""):
            normalized[key] = None
            continue
        try:
            normalized[key] = date.fromisoformat(value).isoformat()
        except (TypeError, ValueError) as error:
            raise ValueError(f"Invalid {key.replace('_', ' ')}.") from error

    if normalized["start_date"] and normalized["end_date"]:
        if normalized["start_date"] > normalized["end_date"]:
            raise ValueError("Start date must not be after end date.")

    for key, value, allowed in (
        ("severity", severity, SEVERITIES),
        ("classification", classification, CLASSIFICATIONS),
        ("incident_status", incident_status, INCIDENT_STATUSES),
        ("category", category, REPORT_CATEGORIES),
    ):
        value = value.strip() if isinstance(value, str) else value
        if value in (None, ""):
            normalized[key] = None
        elif value not in allowed:
            raise ValueError(f"Invalid {key.replace('_', ' ')} filter.")
        else:
            normalized[key] = value
    for key, value in (("record_status", record_status), ("source", source)):
        if value in (None, ""):
            normalized[key] = None
        elif not isinstance(value, str) or len(value.strip()) > 200:
            raise ValueError(f"Invalid {key.replace('_', ' ')} filter.")
        else:
            normalized[key] = value.strip()
    return normalized


def _where_date_and_values(
    date_column,
    filters,
    severity_column=None,
    classification_column=None,
    status_column=None,
    record_status_column=None,
    source_column=None,
):
    clauses = []
    parameters = []
    if filters["start_date"]:
        clauses.append(f"date({date_column}) >= ?")
        parameters.append(filters["start_date"])
    if filters["end_date"]:
        clauses.append(f"date({date_column}) <= ?")
        parameters.append(filters["end_date"])
    if severity_column and filters["severity"]:
        clauses.append(f"{severity_column} = ?")
        parameters.append(filters["severity"])
    if classification_column and filters["classification"]:
        clauses.append(f"{classification_column} = ?")
        parameters.append(filters["classification"])
    if status_column and filters["incident_status"]:
        clauses.append(f"{status_column} = ?")
        parameters.append(filters["incident_status"])
    if record_status_column and filters["record_status"]:
        clauses.append(f"{record_status_column} = ?")
        parameters.append(filters["record_status"])
    if source_column and filters["source"]:
        clauses.append(f"{source_column} LIKE ?")
        parameters.append(f"%{filters['source']}%")
    return (
        f"WHERE {' AND '.join(clauses)}" if clauses else "",
        parameters,
    )


def _query_rows(connection, query, parameters=()):
    return [dict(row) for row in connection.execute(query, parameters).fetchall()]


def get_report_data(**filter_values):
    filters = validate_report_filters(**filter_values)
    reports = {}
    with get_db_connection() as connection:
        category = filters["category"]
        if category in (None, "events"):
            where, parameters = _where_date_and_values(
                "e.received_at",
                filters,
                "e.severity",
                "e.classification",
                source_column="e.source",
            )
            events = _query_rows(
                connection,
                f"""
                SELECT e.id, e.event_reference, e.source, e.event_type,
                       e.severity, e.classification, e.description,
                       e.source_timestamp, e.received_at
                FROM security_events e
                {where}
                ORDER BY e.received_at DESC, e.id DESC
                """,
                parameters,
            )
            severity_counts = {value: 0 for value in sorted(SEVERITIES)}
            classification_counts = {
                value: 0 for value in ("REAL", "SIMULATED", "TEST")
            }
            event_type_counts = {}
            for event in events:
                severity_counts[event["severity"]] = (
                    severity_counts.get(event["severity"], 0) + 1
                )
                classification_counts[event["classification"]] = (
                    classification_counts.get(event["classification"], 0) + 1
                )
                event_type_counts[event["event_type"]] = (
                    event_type_counts.get(event["event_type"], 0) + 1
                )
            reports["events"] = {
                "total": len(events),
                "by_severity": severity_counts,
                "by_classification": classification_counts,
                "by_event_type": sorted(
                    (
                        {"event_type": key, "count": value}
                        for key, value in event_type_counts.items()
                    ),
                    key=lambda item: (-item["count"], item["event_type"]),
                ),
                "records": events,
            }

        if category in (None, "incidents"):
            where, parameters = _where_date_and_values(
                "i.created_at",
                filters,
                "i.severity",
                "i.classification",
                "i.status",
                source_column="e.source",
            )
            incidents = _query_rows(
                connection,
                f"""
                SELECT i.id, i.incident_reference, i.title, i.description,
                       i.severity, i.status, i.classification, i.created_at,
                       i.updated_at, u.username AS assigned_username,
                       e.event_reference AS source_event_reference,
                       (
                           SELECT t.recorded_at
                           FROM incident_timeline t
                           WHERE t.incident_id = i.id
                             AND t.activity = 'Status changed'
                             AND t.details LIKE '% to resolved.%'
                           ORDER BY t.id
                           LIMIT 1
                       ) AS resolved_at
                FROM incidents i
                LEFT JOIN users u ON u.id = i.assigned_to
                LEFT JOIN security_events e ON e.id = i.source_event_id
                {where}
                ORDER BY i.created_at DESC, i.id DESC
                """,
                parameters,
            )
            status_counts = {
                value: 0
                for value in (
                    "open", "investigating", "contained", "resolved", "closed"
                )
            }
            severity_counts = {value: 0 for value in sorted(SEVERITIES)}
            classification_counts = {
                value: 0 for value in ("REAL", "SIMULATED", "TEST")
            }
            for incident in incidents:
                status_counts[incident["status"]] = (
                    status_counts.get(incident["status"], 0) + 1
                )
                severity_counts[incident["severity"]] = (
                    severity_counts.get(incident["severity"], 0) + 1
                )
                classification_counts[incident["classification"]] = (
                    classification_counts.get(incident["classification"], 0) + 1
                )
            reports["incidents"] = {
                "total": len(incidents),
                "by_status": status_counts,
                "by_severity": severity_counts,
                "by_classification": classification_counts,
                "records": incidents,
            }

        if category in (None, "detection"):
            rule_where, rule_parameters = _where_date_and_values(
                "r.created_at",
                filters,
                "r.severity",
            )
            rules = _query_rows(
                connection,
                f"""
                SELECT r.id, r.rule_name, r.event_type, r.severity,
                       r.is_enabled, r.threshold, r.window_minutes,
                       r.created_at, r.updated_at
                FROM detection_rules r
                {rule_where}
                ORDER BY r.rule_name COLLATE NOCASE, r.id
                """,
                rule_parameters,
            )
            alert_where, alert_parameters = _where_date_and_values(
                "a.created_at",
                filters,
                "a.severity",
                "e.classification",
                record_status_column="a.status",
                source_column="e.source",
            )
            alerts = _query_rows(
                connection,
                f"""
                SELECT a.id, a.rule_id, r.rule_name, a.event_id,
                       e.event_reference, e.event_type, e.classification,
                       a.severity, a.status, a.summary, a.created_at
                FROM detection_alerts a
                JOIN detection_rules r ON r.id = a.rule_id
                JOIN security_events e ON e.id = a.event_id
                {alert_where}
                ORDER BY a.created_at DESC, a.id DESC
                """,
                alert_parameters,
            )
            execution_where, execution_parameters = _where_date_and_values(
                "x.executed_at",
                filters,
                "e.severity",
                classification_column="e.classification",
                source_column="e.source",
            )
            executions = _query_rows(
                connection,
                f"""
                SELECT x.id, x.rule_id, r.rule_name, x.event_id,
                       e.event_reference, e.event_type, e.classification,
                       e.severity, x.matched, x.matching_count, x.executed_at
                FROM detection_rule_executions x
                JOIN detection_rules r ON r.id = x.rule_id
                JOIN security_events e ON e.id = x.event_id
                {execution_where}
                ORDER BY x.executed_at DESC, x.id DESC
                LIMIT 500
                """,
                execution_parameters,
            )
            reports["detection"] = {
                "total_rules": len(rules),
                "enabled_rules": sum(bool(rule["is_enabled"]) for rule in rules),
                "disabled_rules": sum(not bool(rule["is_enabled"]) for rule in rules),
                "total_alerts": len(alerts),
                "open_alerts": sum(alert["status"] == "open" for alert in alerts),
                "resolved_alerts": sum(
                    alert["status"] == "resolved" for alert in alerts
                ),
                "alerts_by_severity": {
                    value: sum(alert["severity"] == value for alert in alerts)
                    for value in sorted(SEVERITIES)
                },
                "rules": rules,
                "alerts": alerts,
                "executions": executions,
            }

        if category in (None, "monitoring"):
            where, parameters = _where_date_and_values(
                "m.created_at",
                filters,
                record_status_column="m.connection_status",
                source_column="m.source_name",
            )
            sources = _query_rows(
                connection,
                f"""
                SELECT m.id, m.source_name, m.source_type, m.status,
                       m.monitoring_mode, m.connection_status, m.is_enabled,
                       m.last_checked_at, m.last_successful_check,
                       m.created_at, m.updated_at
                FROM monitoring_sources m
                {where}
                ORDER BY m.source_name COLLATE NOCASE, m.id
                """,
                parameters,
            )
            reports["monitoring"] = {
                "total": len(sources),
                "by_type": _count_by(sources, "source_type"),
                "by_operational_status": _count_by(sources, "status"),
                "by_connection_status": _count_by(sources, "connection_status"),
                "by_mode": _count_by(sources, "monitoring_mode"),
                "records": sources,
            }

        if category in (None, "simulations"):
            where, parameters = _where_date_and_values(
                "s.started_at",
                filters,
                record_status_column="s.status",
            )
            runs = _query_rows(
                connection,
                f"""
                SELECT s.id, s.scenario_name, s.description, s.status,
                       s.events_generated, s.started_at, s.completed_at,
                       u.username AS executed_by_username
                FROM simulation_runs s
                LEFT JOIN users u ON u.id = s.executed_by
                {where}
                ORDER BY s.started_at DESC, s.id DESC
                """,
                parameters,
            )
            event_where = "WHERE classification = 'SIMULATED' AND raw_data IS NOT NULL"
            event_parameters = []
            if filters["severity"]:
                event_where += " AND severity = ?"
                event_parameters.append(filters["severity"])
            if filters["source"]:
                event_where += " AND source LIKE ?"
                event_parameters.append(f"%{filters['source']}%")
            event_rows = _query_rows(
                connection,
                f"""
                SELECT id, event_reference, event_type, source, raw_data
                FROM security_events
                {event_where}
                """,
                tuple(event_parameters),
            )
            run_ids_by_event = {}
            for event in event_rows:
                try:
                    run_id = json.loads(event["raw_data"]).get("simulation_run_id")
                except (TypeError, ValueError, AttributeError):
                    continue
                if type(run_id) is int:
                    run_ids_by_event[event["id"]] = run_id

            alerts = _query_rows(
                connection,
                """
                SELECT a.id, a.event_id, a.severity, a.status, a.created_at,
                       r.rule_name, e.event_reference
                FROM detection_alerts a
                JOIN detection_rules r ON r.id = a.rule_id
                JOIN security_events e ON e.id = a.event_id
                WHERE e.classification = 'SIMULATED'
                ORDER BY a.created_at DESC, a.id DESC
                """,
            )
            alerts_by_run = {}
            for alert in alerts:
                run_id = run_ids_by_event.get(alert["event_id"])
                if run_id is not None:
                    alerts_by_run.setdefault(run_id, []).append(alert)
            for run in runs:
                run["alerts"] = alerts_by_run.get(run["id"], [])
                if filters["severity"]:
                    run["alerts"] = [
                        alert for alert in run["alerts"]
                        if alert["severity"] == filters["severity"]
                    ]
            if (
                filters["classification"]
                and filters["classification"] != "SIMULATED"
            ):
                runs = []
            elif filters["severity"] or filters["source"]:
                matching_run_ids = set(run_ids_by_event.values())
                runs = [
                    run for run in runs
                    if run["id"] in matching_run_ids
                ]
            reports["simulations"] = {
                "total": len(runs),
                "by_scenario": _count_by(runs, "scenario_name"),
                "runs": runs,
            }

        if category in (None, "ingestion"):
            where, parameters = _where_date_and_values(
                "j.started_at",
                filters,
                record_status_column="j.status",
                source_column="s.source_name",
            )
            jobs = _query_rows(
                connection,
                f"""
                SELECT j.id, j.source_id, s.source_name, j.status,
                       j.events_seen, j.events_ingested, j.duplicates_skipped,
                       j.error_summary, j.started_at, j.completed_at,
                       u.username AS started_by_username
                FROM monitoring_ingestion_jobs j
                LEFT JOIN monitoring_sources s ON s.id = j.source_id
                LEFT JOIN users u ON u.id = j.started_by
                {where}
                ORDER BY j.started_at DESC, j.id DESC
                """,
                parameters,
            )
            reports["ingestion"] = {
                "total": len(jobs),
                "by_status": _count_by(jobs, "status"),
                "events_ingested": sum(job["events_ingested"] for job in jobs),
                "duplicates_skipped": sum(
                    job["duplicates_skipped"] for job in jobs
                ),
                "records": jobs,
            }

        if category in (None, "actions"):
            where, parameters = _where_date_and_values(
                "a.created_at",
                filters,
                "i.severity",
                "i.classification",
                "i.status",
                record_status_column="a.action_status",
                source_column="e.source",
            )
            actions = _query_rows(
                connection,
                f"""
                SELECT a.id, a.incident_id, i.incident_reference, i.title,
                       i.severity, i.classification, i.status AS incident_status,
                       e.source AS event_source, a.action_type, a.description,
                       a.action_status, a.created_at, a.updated_at,
                       a.completed_at, performer.username AS performed_by_username,
                       updater.username AS updated_by_username
                FROM incident_actions a
                JOIN incidents i ON i.id = a.incident_id
                LEFT JOIN security_events e ON e.id = i.source_event_id
                LEFT JOIN users performer ON performer.id = a.performed_by
                LEFT JOIN users updater ON updater.id = a.updated_by
                {where}
                ORDER BY a.created_at DESC, a.id DESC
                """,
                parameters,
            )
            reports["actions"] = {
                "total": len(actions),
                "by_status": _count_by(actions, "action_status"),
                "by_type": _count_by(actions, "action_type"),
                "records": actions,
            }

        if category in (None, "evidence"):
            where, parameters = _where_date_and_values(
                "e.collected_at",
                filters,
                "i.severity",
                "i.classification",
                "i.status",
                source_column="source_event.source",
            )
            evidence = _query_rows(
                connection,
                f"""
                SELECT e.id, e.evidence_reference, e.incident_id,
                       i.incident_reference, i.title, i.severity,
                       i.classification, i.status AS incident_status,
                       source_event.source AS event_source,
                       e.evidence_type, e.description, e.original_filename,
                       e.file_size, e.mime_type, e.sha256_hash, e.collected_at,
                       collector.username AS collected_by_username
                FROM incident_evidence e
                JOIN incidents i ON i.id = e.incident_id
                LEFT JOIN security_events source_event
                    ON source_event.id = i.source_event_id
                LEFT JOIN users collector ON collector.id = e.collected_by
                {where}
                ORDER BY e.collected_at DESC, e.id DESC
                """,
                parameters,
            )
            custody_where, custody_parameters = _where_date_and_values(
                "c.recorded_at",
                filters,
                "i.severity",
                "i.classification",
                "i.status",
                record_status_column="c.action",
                source_column="source_event.source",
            )
            custody = _query_rows(
                connection,
                f"""
                SELECT c.id, c.evidence_id, e.evidence_reference,
                       i.incident_reference, c.action, c.details,
                       c.recorded_at, u.username AS actor_username,
                       c.actor_id
                FROM incident_evidence_custody c
                JOIN incident_evidence e ON e.id = c.evidence_id
                JOIN incidents i ON i.id = e.incident_id
                LEFT JOIN security_events source_event
                    ON source_event.id = i.source_event_id
                LEFT JOIN users u ON u.id = c.actor_id
                {custody_where}
                ORDER BY c.recorded_at DESC, c.id DESC
                """,
                custody_parameters,
            )
            reports["evidence"] = {
                "total": len(evidence),
                "custody_entries": len(custody),
                "records": evidence,
                "custody": custody,
            }

        if category in (None, "audit"):
            where, parameters = _where_date_and_values(
                "a.recorded_at",
                filters,
                record_status_column="a.action",
                source_column="u.username",
            )
            audit_records = _query_rows(
                connection,
                f"""
                SELECT a.id, a.user_id, u.username, u.role,
                       a.action, a.details, a.recorded_at
                FROM system_audit_logs a
                LEFT JOIN users u ON u.id = a.user_id
                {where}
                ORDER BY a.recorded_at DESC, a.id DESC
                LIMIT 1000
                """,
                parameters,
            )
            audit_total = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM system_audit_logs a
                LEFT JOIN users u ON u.id = a.user_id
                {where}
                """,
                parameters,
            ).fetchone()[0]
            for record in audit_records:
                record["details"] = redact_sensitive_text(record["details"])
            reports["audit"] = {
                "total": audit_total,
                "displayed": len(audit_records),
                "by_action": _count_by(audit_records, "action"),
                "records": audit_records,
            }
    return {"filters": filters, "reports": reports}


def _count_by(records, key):
    counts = {}
    for record in records:
        value = record.get(key) or "Unknown"
        counts[value] = counts.get(value, 0) + 1
    return [
        {"label": label, "count": count}
        for label, count in sorted(counts.items(), key=lambda item: str(item[0]))
    ]


def get_report_export_rows(category, **filter_values):
    filters = validate_report_filters(category=category, **filter_values)
    data = get_report_data(**filters)
    reports = data["reports"]
    rows = []

    if category == "events":
        for item in reports["events"]["records"]:
            rows.append([
                "Security event", item["event_reference"], item["event_type"],
                item["source"], item["severity"], item["classification"],
                "", item["received_at"], item["description"],
            ])
    elif category == "incidents":
        for item in reports["incidents"]["records"]:
            rows.append([
                "Incident", item["incident_reference"], item["title"],
                item["source_event_reference"] or "", item["severity"],
                item["classification"], item["status"], item["created_at"],
                item["resolved_at"] or "", item["assigned_username"] or "",
                item["description"] or "",
            ])
    elif category == "detection":
        for item in reports["detection"]["rules"]:
            rows.append([
                "Detection rule", item["id"], item["rule_name"],
                item["event_type"], item["severity"],
                "Enabled" if item["is_enabled"] else "Disabled",
                item["created_at"], item["threshold"], item["window_minutes"],
            ])
        for item in reports["detection"]["alerts"]:
            rows.append([
                "Detection alert", item["id"], item["rule_name"],
                item["event_reference"], item["severity"],
                f"{item['classification']} / {item['status']}",
                item["created_at"], "", item["summary"],
            ])
        for item in reports["detection"]["executions"]:
            rows.append([
                "Rule execution", item["id"], item["rule_name"],
                item["event_reference"],
                f"{item['severity']} / "
                f"{'Matched' if item['matched'] else 'Not matched'}",
                item["classification"], item["executed_at"],
                item["matching_count"], "",
            ])
    elif category == "monitoring":
        for item in reports["monitoring"]["records"]:
            rows.append([
                "Monitoring source", item["id"], item["source_name"],
                item["source_type"], item["monitoring_mode"],
                item["connection_status"], item["status"],
                item["last_checked_at"] or "", item["last_successful_check"] or "",
            ])
    elif category == "simulations":
        for item in reports["simulations"]["runs"]:
            alert_summary = "; ".join(
                f"{alert['rule_name']} ({alert['severity']}, {alert['status']})"
                for alert in item["alerts"]
            )
            rows.append([
                "Simulation run", item["id"], item["scenario_name"],
                item["status"], item["started_at"], item["completed_at"] or "",
                item["executed_by_username"] or "", item["events_generated"],
                alert_summary,
            ])
    elif category == "ingestion":
        for item in reports["ingestion"]["records"]:
            rows.append([
                "Monitoring ingestion job", item["id"], item["source_name"] or "",
                item["status"], item["started_at"], item["completed_at"] or "",
                item["started_by_username"] or "", item["events_seen"],
                item["events_ingested"], item["duplicates_skipped"],
                item["error_summary"] or "",
            ])
    elif category == "actions":
        for item in reports["actions"]["records"]:
            rows.append([
                "Incident response action", item["id"],
                item["incident_reference"], item["action_type"],
                item["action_status"], item["severity"], item["classification"],
                item["performed_by_username"] or "", item["created_at"],
                item["completed_at"] or "", item["description"],
            ])
    elif category == "evidence":
        for item in reports["evidence"]["records"]:
            rows.append([
                "Incident evidence", item["evidence_reference"] or item["id"],
                item["incident_reference"], item["evidence_type"],
                item["original_filename"] or "Metadata/reference only",
                item["file_size"] or "", item["mime_type"] or "",
                item["sha256_hash"] or "", item["collected_at"],
                item["collected_by_username"] or "", item["description"] or "",
            ])
        for item in reports["evidence"]["custody"]:
            rows.append([
                "Evidence custody", item["id"], item["incident_reference"],
                item["evidence_reference"] or "", item["action"],
                "", "", "", item["recorded_at"],
                item["actor_username"] or "System", item["details"] or "",
            ])
    elif category == "audit":
        for item in reports["audit"]["records"]:
            rows.append([
                "System audit", item["id"], item["username"] or "System",
                item["role"] or "", item["action"], item["recorded_at"],
                item["details"] or "",
            ])
    return rows
