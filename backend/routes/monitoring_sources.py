from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from backend.services.monitoring_source_service import (
    ALLOWED_CONNECTION_STATUSES,
    ALLOWED_MONITORING_MODES,
    ALLOWED_SOURCE_TYPES,
    create_monitoring_source,
    ensure_default_monitoring_sources,
    get_monitoring_source_by_id,
    get_monitoring_sources,
    record_monitoring_check,
    update_monitoring_source,
    update_monitoring_source_status,
)
from backend.services.ingestion_service import get_ingestion_jobs, run_source_poll
from backend.utils.security import (
    get_csrf_token,
    login_required,
    validate_csrf_token,
)

monitoring_sources_bp = Blueprint("monitoring_sources", __name__)


def _user_is_admin():
    return session.get("role") == "admin"


@monitoring_sources_bp.route("/monitoring-sources", methods=["GET"])
@login_required
def monitoring_sources_list():
    get_csrf_token()
    source_type = request.args.get("source_type", "").strip().upper()
    monitoring_mode = request.args.get("monitoring_mode", "").strip().upper()
    connection_status = request.args.get("connection_status", "").strip().upper()
    enabled = request.args.get("is_enabled", "")
    search_query = request.args.get("search", "").strip()

    if source_type not in {"", *ALLOWED_SOURCE_TYPES}:
        source_type = ""
    if monitoring_mode not in {"", *ALLOWED_MONITORING_MODES}:
        monitoring_mode = ""
    if connection_status not in {"", *ALLOWED_CONNECTION_STATUSES}:
        connection_status = ""

    enabled_filter = None
    if enabled in {"true", "false"}:
        enabled_filter = enabled == "true"

    sources = get_monitoring_sources(
        source_type=source_type or None,
        monitoring_mode=monitoring_mode or None,
        connection_status=connection_status or None,
        is_enabled=enabled_filter,
        search_query=search_query or None,
    )

    return render_template(
        "monitoring_sources.html",
        sources=sources,
        source_type_filter=source_type,
        monitoring_mode_filter=monitoring_mode,
        connection_status_filter=connection_status,
        enabled_filter=enabled,
        search_query=search_query,
        total_sources=len(sources),
        ingestion_jobs=get_ingestion_jobs(),
    )


@monitoring_sources_bp.route("/monitoring-sources/new", methods=["GET", "POST"])
@login_required
def monitoring_source_new():
    if not _user_is_admin():
        flash("Only administrators can create monitoring sources.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    get_csrf_token()

    if request.method == "GET":
        return render_template(
            "monitoring_source_form.html",
            source=None,
            form_title="Register Monitoring Source",
            submit_label="Create Source",
            source_types=sorted(ALLOWED_SOURCE_TYPES),
            monitoring_modes=sorted(ALLOWED_MONITORING_MODES),
            connection_statuses=sorted(ALLOWED_CONNECTION_STATUSES),
        )

    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    try:
        source_id = create_monitoring_source(
            source_name=request.form.get("source_name"),
            source_type=request.form.get("source_type"),
            monitoring_mode=request.form.get("monitoring_mode"),
            description=request.form.get("description"),
            connection_status=request.form.get("connection_status"),
            is_enabled=request.form.get("is_enabled") == "on",
            created_by=session.get("user_id"),
        )
        flash("Monitoring source created successfully.", "success")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))
    except ValueError as error:
        flash(str(error), "error")
        return render_template(
            "monitoring_source_form.html",
            source={
                "source_name": request.form.get("source_name", ""),
                "source_type": request.form.get("source_type", ""),
                "monitoring_mode": request.form.get("monitoring_mode", "PLANNED"),
                "description": request.form.get("description", ""),
                "connection_status": request.form.get("connection_status", "NOT_CONNECTED"),
                "is_enabled": request.form.get("is_enabled") == "on",
            },
            form_title="Register Monitoring Source",
            submit_label="Create Source",
            source_types=sorted(ALLOWED_SOURCE_TYPES),
            monitoring_modes=sorted(ALLOWED_MONITORING_MODES),
            connection_statuses=sorted(ALLOWED_CONNECTION_STATUSES),
        )


@monitoring_sources_bp.route("/monitoring-sources/<int:source_id>", methods=["GET"])
@login_required
def monitoring_source_detail(source_id):
    source = get_monitoring_source_by_id(source_id)
    if source is None:
        flash("Monitoring source not found.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    return render_template(
        "monitoring_source_detail.html",
        source=source,
        ingestion_jobs=get_ingestion_jobs(source_id=source_id),
    )


@monitoring_sources_bp.route("/monitoring-sources/<int:source_id>/edit", methods=["GET", "POST"])
@login_required
def monitoring_source_edit(source_id):
    if not _user_is_admin():
        flash("Only administrators can edit monitoring sources.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    source = get_monitoring_source_by_id(source_id)
    if source is None:
        flash("Monitoring source not found.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    get_csrf_token()

    if request.method == "GET":
        return render_template(
            "monitoring_source_form.html",
            source=source,
            form_title="Edit Monitoring Source",
            submit_label="Save Changes",
            source_types=sorted(ALLOWED_SOURCE_TYPES),
            monitoring_modes=sorted(ALLOWED_MONITORING_MODES),
            connection_statuses=sorted(ALLOWED_CONNECTION_STATUSES),
        )

    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    try:
        update_monitoring_source(
            source_id=source_id,
            source_name=request.form.get("source_name"),
            source_type=request.form.get("source_type"),
            monitoring_mode=request.form.get("monitoring_mode"),
            description=request.form.get("description"),
            connection_status=request.form.get("connection_status"),
            is_enabled=request.form.get("is_enabled") == "on",
            updated_by=session.get("user_id"),
        )
        flash("Monitoring source updated successfully.", "success")
    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))


@monitoring_sources_bp.route("/monitoring-sources/<int:source_id>/status", methods=["POST"])
@login_required
def monitoring_source_status(source_id):
    if not _user_is_admin():
        flash("Only administrators can change monitoring source status.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    source = get_monitoring_source_by_id(source_id)
    if source is None:
        flash("Monitoring source not found.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    status_code = (request.form.get("status") or "").strip().upper()
    try:
        update_monitoring_source_status(
            source_id,
            status_code,
            updated_by=session.get("user_id"),
        )
        flash("Monitoring source status updated successfully.", "success")
    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))


@monitoring_sources_bp.route("/monitoring-sources/<int:source_id>/check", methods=["POST"])
@login_required
def monitoring_source_check(source_id):
    if not _user_is_admin():
        flash("Only administrators can perform checks for monitoring sources.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    source = get_monitoring_source_by_id(source_id)
    if source is None:
        flash("Monitoring source not found.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    check_result = (request.form.get("result") or "").strip().lower()
    error_message = (request.form.get("error") or "").strip()
    if check_result not in {"success", "failure"}:
        flash("Please specify whether the check succeeded or failed.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    try:
        result = record_monitoring_check(
            source_id=source_id,
            success=check_result == "success",
            error=error_message if check_result == "failure" else None,
            checked_by=session.get("user_id"),
        )
        if result is not None:
            if check_result == "success":
                flash("Manual administrative check recorded; no live external connection was established.", "success")
            else:
                flash("Manual check failure recorded; connection state and prior successful verification were preserved.", "warning")
    except ValueError as error:
        flash(str(error), "error")

    return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))


@monitoring_sources_bp.route(
    "/monitoring-sources/<int:source_id>/poll",
    methods=["POST"],
)
@login_required
def monitoring_source_poll(source_id):
    if not _user_is_admin():
        flash("Only administrators can start monitoring polls.", "error")
        return redirect(
            url_for("monitoring_sources.monitoring_source_detail", source_id=source_id)
        )

    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(url_for("monitoring_sources.monitoring_source_detail", source_id=source_id))

    try:
        job = run_source_poll(source_id, session.get("user_id"))
        if job["status"] == "completed":
            flash(
                f"Poll completed: {job['events_ingested']} event(s) ingested.",
                "success",
            )
        else:
            flash(
                f"Poll {job['status']}: {job['error_summary'] or 'No events were ingested.'}",
                "warning",
            )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(
        url_for("monitoring_sources.monitoring_source_detail", source_id=source_id)
    )


@monitoring_sources_bp.route("/monitoring-sources/setup", methods=["POST"])
@login_required
def monitoring_source_setup():
    if not _user_is_admin():
        flash("Only administrators can initialize default monitoring sources.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry the form.", "error")
        return redirect(url_for("monitoring_sources.monitoring_sources_list"))

    ensure_default_monitoring_sources()
    flash("Default monitoring sources were initialized.", "success")
    return redirect(url_for("monitoring_sources.monitoring_sources_list"))
