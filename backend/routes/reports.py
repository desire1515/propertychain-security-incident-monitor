import csv
from io import StringIO

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    render_template,
    request,
    session,
)

from backend.services.report_service import (
    REPORT_CATEGORIES,
    get_report_data,
    get_report_export_rows,
    validate_report_filters,
)
from backend.utils.security import login_required

reports_bp = Blueprint("reports", __name__)

CSV_COLUMNS = {
    "events": [
        "Record type", "Event reference", "Event type", "Source", "Severity",
        "Classification", "Status", "Received at", "Description",
    ],
    "incidents": [
        "Record type", "Incident reference", "Title", "Source event",
        "Severity", "Classification", "Status", "Created at", "Resolved at",
        "Assigned analyst", "Description",
    ],
    "detection": [
        "Record type", "ID", "Rule name", "Event type/reference",
        "Severity/result", "Classification/status", "Timestamp",
        "Count/threshold", "Details/window",
    ],
    "monitoring": [
        "Record type", "ID", "Source name", "Source type", "Monitoring mode",
        "Connection status", "Operational status", "Last checked",
        "Last successful check",
    ],
    "simulations": [
        "Record type", "ID", "Scenario", "Run status", "Started at",
        "Completed at", "Initiated by", "Events generated", "Related alerts",
    ],
    "ingestion": [
        "Record type", "Job ID", "Source", "Status", "Started at",
        "Completed at", "Started by", "Events seen", "Events ingested",
        "Duplicates skipped", "Error summary",
    ],
    "actions": [
        "Record type", "Action ID", "Incident", "Action type", "Status",
        "Severity", "Classification", "Recorded by", "Created at",
        "Completed at", "Description",
    ],
    "evidence": [
        "Record type", "Evidence reference", "Incident", "Evidence type",
        "Filename or custody action", "File size", "MIME type", "SHA-256",
        "Recorded at", "Actor", "Details",
    ],
    "audit": [
        "Record type", "Audit ID", "User", "Role", "Action", "Recorded at",
        "Details",
    ],
}


def _require_report_user():
    if session.get("role") not in {"admin", "analyst"}:
        abort(403)


def _request_filters():
    category = request.args.get("category") or None
    if category == "all":
        category = None
    return validate_report_filters(
        start_date=request.args.get("start_date") or None,
        end_date=request.args.get("end_date") or None,
        severity=request.args.get("severity") or None,
        classification=request.args.get("classification") or None,
        incident_status=request.args.get("incident_status") or None,
        record_status=request.args.get("record_status") or None,
        source=request.args.get("source") or None,
        category=category,
    )


def _spreadsheet_safe(value):
    if value is None:
        return ""
    text = str(value)
    if text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


@reports_bp.route("/reports", methods=["GET"])
@login_required
def reports_dashboard():
    _require_report_user()
    try:
        filters = _request_filters()
        data = get_report_data(**filters)
    except ValueError as error:
        flash(str(error), "error")
        filters = validate_report_filters()
        data = get_report_data()
    return render_template(
        "reports.html",
        data=data,
        categories=sorted(REPORT_CATEGORIES),
        severities=["low", "medium", "high", "critical"],
        classifications=["REAL", "SIMULATED", "TEST"],
        incident_statuses=[
            "open", "investigating", "contained", "resolved", "closed"
        ],
        filters=filters,
    )


@reports_bp.route("/reports/export.csv", methods=["GET"])
@login_required
def export_report():
    _require_report_user()
    category = request.args.get("category", "")
    if category not in REPORT_CATEGORIES:
        abort(400, description="Choose a valid report category for CSV export.")
    try:
        filters = validate_report_filters(
            start_date=request.args.get("start_date") or None,
            end_date=request.args.get("end_date") or None,
            severity=request.args.get("severity") or None,
            classification=request.args.get("classification") or None,
            incident_status=request.args.get("incident_status") or None,
            record_status=request.args.get("record_status") or None,
            source=request.args.get("source") or None,
            category=category,
        )
        rows = get_report_export_rows(category, **{
            key: value for key, value in filters.items() if key != "category"
        })
    except ValueError as error:
        abort(400, description=str(error))

    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(CSV_COLUMNS[category])
    for row in rows:
        writer.writerow([_spreadsheet_safe(value) for value in row])
    response = Response(output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="pcsirm-{category}-report.csv"'
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
