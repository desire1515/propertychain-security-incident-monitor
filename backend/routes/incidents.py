
from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for
)

from backend.utils.security import (
    get_csrf_token,
    login_required,
    validate_csrf_token,
)
from backend.services.incident_service import (
    add_incident_action,
    add_incident_evidence,
    assign_incident,
    create_incident_from_event as create_incident_from_security_event,
    get_assignable_incident_users,
    get_incidents,
    get_incident_actions,
    get_incident_by_event_reference,
    get_incident_by_reference,
    get_incident_evidence,
    get_incident_evidence_custody,
    get_incident_evidence_by_id,
    record_incident_evidence_access,
    update_incident_status,
    update_incident_action_status,
    verify_incident_evidence,
)
from database.db import get_db_connection

incidents_bp = Blueprint("incidents", __name__)

ALLOWED_STATUS_VALUES = [
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed",
]
ALLOWED_SEVERITY_VALUES = ["low", "medium", "high", "critical"]
ALLOWED_CLASSIFICATION_VALUES = ["REAL", "SIMULATED", "TEST"]


def _require_incident_user():
    if session.get("role") not in {"admin", "analyst"}:
        abort(403)


@incidents_bp.route("/incidents", methods=["GET"])
@login_required
def incident_list():
    _require_incident_user()
    incidents = get_incidents()

    status_filter = request.args.get("status", "").strip().lower()
    severity_filter = request.args.get("severity", "").strip().lower()
    classification_filter = request.args.get("classification", "").strip().upper()

    if status_filter not in set(ALLOWED_STATUS_VALUES):
        status_filter = ""

    if severity_filter not in set(ALLOWED_SEVERITY_VALUES):
        severity_filter = ""

    if classification_filter not in set(ALLOWED_CLASSIFICATION_VALUES):
        classification_filter = ""

    if status_filter:
        incidents = [
            item for item in incidents
            if item["status"] == status_filter
        ]

    if severity_filter:
        incidents = [
            item for item in incidents
            if item["severity"] == severity_filter
        ]

    if classification_filter:
        incidents = [
            item for item in incidents
            if item["classification"] == classification_filter
        ]

    return render_template(
        "incidents.html",
        incidents=incidents,
        status_filter=status_filter,
        severity_filter=severity_filter,
        classification_filter=classification_filter,
        total_incidents=len(incidents)
    )


@incidents_bp.route("/incidents/<incident_reference>", methods=["GET"])
@login_required
def incident_detail(incident_reference):
    _require_incident_user()
    get_csrf_token()
    incident = get_incident_by_reference(incident_reference)

    if incident is None:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents.incident_list"))

    source_event = None
    with get_db_connection() as connection:
        if incident.get("source_event_id") is not None:
            source_event = connection.execute(
                """
                SELECT *
                FROM security_events
                WHERE id = ?
                """,
                (incident["source_event_id"],)
            ).fetchone()

        timeline = connection.execute(
            """
            SELECT *
            FROM incident_timeline
            WHERE incident_id = ?
            ORDER BY recorded_at ASC, id ASC
            """,
            (incident["id"],)
        ).fetchall()

    evidence = get_incident_evidence(incident["id"])
    for evidence_item in evidence:
        evidence_item["custody_history"] = get_incident_evidence_custody(
            evidence_item["id"]
        )

    return render_template(
        "incident_detail.html",
        incident=incident,
        source_event=dict(source_event) if source_event else None,
        timeline=[dict(item) for item in timeline],
        status_options=ALLOWED_STATUS_VALUES,
        evidence=evidence,
        actions=get_incident_actions(incident["id"]),
        can_assign=session.get("role") == "admin",
        is_admin=session.get("role") == "admin",
        assignable_users=(
            get_assignable_incident_users()
            if session.get("role") == "admin"
            else []
        ),
    )


@incidents_bp.route(
    "/events/<event_reference>/incidents/new",
    methods=["GET", "POST"],
)
@login_required
def create_incident_from_event(event_reference):
    _require_incident_user()
    with get_db_connection() as connection:
        event = connection.execute(
            "SELECT * FROM security_events WHERE event_reference = ?",
            (event_reference.strip(),),
        ).fetchone()

    if event is None:
        flash("Security event not found.", "error")
        return redirect(url_for("events.security_events"))

    event = dict(event)
    existing_incident = get_incident_by_event_reference(event_reference)
    if existing_incident is not None:
        flash("This event is already linked to an incident.", "info")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=existing_incident["incident_reference"],
            )
        )

    default_title = (
        f"{event['event_type'].replace('_', ' ').title()} "
        f"- {event['event_reference']}"
    )
    default_description = (
        f"Originating security event: {event['event_reference']}\n"
        f"Source: {event['source']}\n"
        f"Event description: {event['description']}"
    )
    values = {
        "title": request.form.get("title", default_title),
        "description": request.form.get("description", default_description),
        "severity": request.form.get("severity", event["severity"]),
    }

    if request.method == "POST":
        if not validate_csrf_token():
            flash("The security token is missing or invalid. Please retry.", "error")
            return redirect(
                url_for(
                    "incidents.create_incident_from_event",
                    event_reference=event_reference,
                )
            )
        try:
            incident_reference = create_incident_from_security_event(
                event_reference=event_reference,
                title=values["title"],
                description=values["description"],
                severity=values["severity"],
                created_by=session.get("user_id"),
            )
            flash("Incident created from the security event.", "success")
            return redirect(
                url_for(
                    "incidents.incident_detail",
                    incident_reference=incident_reference,
                )
            )
        except ValueError as error:
            existing_incident = get_incident_by_event_reference(event_reference)
            if existing_incident is not None:
                flash("This event is already linked to an incident.", "info")
                return redirect(
                    url_for(
                        "incidents.incident_detail",
                        incident_reference=existing_incident["incident_reference"],
                    )
                )
            flash(str(error), "error")
            return render_template(
                "incident_create.html",
                event=event,
                values=values,
                severity_options=ALLOWED_SEVERITY_VALUES,
            ), 400

    get_csrf_token()
    return render_template(
        "incident_create.html",
        event=event,
        values=values,
        severity_options=ALLOWED_SEVERITY_VALUES,
    )


@incidents_bp.route(
    "/incidents/<incident_reference>/assignment",
    methods=["POST"],
)
@login_required
def change_incident_assignment(incident_reference):
    _require_incident_user()
    if session.get("role") != "admin":
        flash("Only administrators can assign or unassign incidents.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )

    assignee_value = request.form.get("assigned_to", "")
    try:
        if assignee_value and not assignee_value.isdecimal():
            raise ValueError("Select an active analyst or choose unassigned.")
        assigned_to = int(assignee_value) if assignee_value else None
        changed = assign_incident(
            incident_reference,
            assigned_to=assigned_to,
            assigned_by=session.get("user_id"),
        )
        flash(
            "Incident assignment updated." if changed else "Incident assignment was unchanged.",
            "success" if changed else "info",
        )
    except ValueError as error:
        flash(str(error), "error")

    return redirect(
        url_for(
            "incidents.incident_detail",
            incident_reference=incident_reference,
        )
    )


@incidents_bp.route("/incidents/<incident_reference>/status", methods=["POST"])
@login_required
def change_incident_status(incident_reference):
    _require_incident_user()
    if session.get("role") != "admin":
        flash("Only administrators can change incident status.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )

    new_status = (request.form.get("status", "") or "").strip().lower()
    updated_by = session.get("user_id")

    if new_status not in set(ALLOWED_STATUS_VALUES):
        flash("Please choose a valid incident status.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )

    try:
        updated = update_incident_status(
            incident_reference=incident_reference,
            new_status=new_status,
            updated_by=updated_by,
        )
        if updated:
            flash("Incident status updated successfully.", "success")
        else:
            flash("The incident already has this status.", "info")
    except ValueError as error:
        flash(str(error), "error")

    return redirect(
        url_for(
            "incidents.incident_detail",
            incident_reference=incident_reference,
        )
    )


@incidents_bp.route(
    "/incidents/<incident_reference>/evidence",
    methods=["POST"],
)
@login_required
def collect_incident_evidence(incident_reference):
    _require_incident_user()
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )

    incident = get_incident_by_reference(incident_reference)
    if incident is None:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents.incident_list"))
    try:
        add_incident_evidence(
            incident_id=incident["id"],
            evidence_type=request.form.get("evidence_type"),
            description=request.form.get("description"),
            evidence_data=request.form.get("evidence_data") or None,
            collected_by=session.get("user_id"),
            file_stream=(
                request.files["evidence_file"].stream
                if request.files.get("evidence_file")
                and request.files["evidence_file"].filename
                else None
            ),
            original_filename=(
                request.files["evidence_file"].filename
                if request.files.get("evidence_file")
                and request.files["evidence_file"].filename
                else None
            ),
        )
        flash(
            "Evidence file uploaded and recorded."
            if request.files.get("evidence_file")
            and request.files["evidence_file"].filename
            else "Evidence record added. Evidence records are append-only.",
            "success",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(
        url_for(
            "incidents.incident_detail",
            incident_reference=incident_reference,
        )
    )


@incidents_bp.route(
    "/incidents/evidence/<int:evidence_id>/download",
    methods=["GET"],
)
@login_required
def download_incident_evidence(evidence_id):
    _require_incident_user()
    try:
        evidence, evidence_path = record_incident_evidence_access(
            evidence_id,
            session.get("user_id"),
        )
    except ValueError:
        abort(404)

    response = send_file(
        evidence_path,
        mimetype=evidence["mime_type"] or "application/octet-stream",
        as_attachment=True,
        download_name=evidence["original_filename"] or evidence["evidence_reference"],
        max_age=0,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@incidents_bp.route(
    "/incidents/evidence/<int:evidence_id>/verify",
    methods=["POST"],
)
@login_required
def verify_incident_evidence_file(evidence_id):
    _require_incident_user()
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(url_for("incidents.incident_list"))
    evidence = get_incident_evidence_by_id(evidence_id)
    if evidence is None:
        flash("Evidence record not found.", "error")
        return redirect(url_for("incidents.incident_list"))
    try:
        result = verify_incident_evidence(
            evidence_id,
            session.get("user_id"),
        )
        flash(
            "Evidence integrity verified."
            if result["verified"]
            else "Evidence integrity mismatch; preserve the file for investigation.",
            "success" if result["verified"] else "error",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(
        url_for(
            "incidents.incident_detail",
            incident_reference=evidence["incident_reference"],
        )
    )


@incidents_bp.route(
    "/incidents/<incident_reference>/actions",
    methods=["POST"],
)
@login_required
def record_incident_action(incident_reference):
    _require_incident_user()
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )

    incident = get_incident_by_reference(incident_reference)
    if incident is None:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents.incident_list"))
    try:
        add_incident_action(
            incident_id=incident["id"],
            action_type=request.form.get("action_type"),
            description=request.form.get("description"),
            performed_by=session.get("user_id"),
        )
        flash(
            "Response recommendation recorded; PCSIRM did not execute it.",
            "success",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(
        url_for(
            "incidents.incident_detail",
            incident_reference=incident_reference,
        )
    )


@incidents_bp.route(
    "/incidents/<incident_reference>/actions/<int:action_id>/status",
    methods=["POST"],
)
@login_required
def change_incident_action_status(incident_reference, action_id):
    _require_incident_user()
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )

    incident = get_incident_by_reference(incident_reference)
    if incident is None:
        flash("Incident not found.", "error")
        return redirect(url_for("incidents.incident_list"))
    requested_status = request.form.get("status", "")
    if (
        session.get("role") == "analyst"
        and requested_status.strip().lower() != "in_progress"
    ):
        flash(
            "Analysts may only move approved recommendations to in progress.",
            "error",
        )
        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_reference=incident_reference,
            )
        )
    try:
        if not any(
            action["id"] == action_id
            for action in get_incident_actions(incident["id"])
        ):
            raise ValueError("Response action not found.")
        changed = update_incident_action_status(
            action_id,
            requested_status,
            updated_by=session.get("user_id"),
        )
        flash(
            "Response action status updated." if changed else "Response action was unchanged.",
            "success" if changed else "info",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(
        url_for(
            "incidents.incident_detail",
            incident_reference=incident_reference,
        )
    )
