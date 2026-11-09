from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from backend.services.detection_rule_service import (
    ALLOWED_ALERT_STATUSES,
    ALLOWED_RULE_SEVERITIES,
    create_detection_rule,
    get_detection_rule_by_id,
    get_detection_alerts,
    get_detection_alert_history,
    get_detection_rules,
    set_detection_alert_status,
    set_detection_rule_enabled,
    update_detection_rule,
)
from backend.utils.security import login_required, validate_csrf_token

detection_rules_bp = Blueprint("detection_rules", __name__)


def _user_is_admin():
    return session.get("role") == "admin"


@detection_rules_bp.route("/detection-rules", methods=["GET", "POST"])
@login_required
def detection_rule_list():
    if request.method == "POST":
        if not _user_is_admin():
            flash("Only administrators can change detection rules.", "error")
            return redirect(url_for("detection_rules.detection_rule_list"))
        if not validate_csrf_token():
            flash("The security token is missing or invalid. Please retry.", "error")
            return redirect(url_for("detection_rules.detection_rule_list"))

        try:
            create_detection_rule(
                rule_name=request.form.get("rule_name"),
                description=request.form.get("description"),
                event_type=request.form.get("event_type"),
                severity=request.form.get("severity"),
                threshold=int(request.form.get("threshold", "")),
                window_minutes=int(request.form.get("window_minutes", "")),
                created_by=session.get("user_id"),
            )
            flash("Detection rule created successfully.", "success")
        except ValueError as error:
            flash(str(error), "error")
        return redirect(url_for("detection_rules.detection_rule_list"))

    return render_template(
        "detection_rules.html",
        rules=get_detection_rules(),
        severities=sorted(ALLOWED_RULE_SEVERITIES),
    )


@detection_rules_bp.route(
    "/detection-rules/<int:rule_id>/enabled",
    methods=["POST"],
)
@login_required
def detection_rule_enabled(rule_id):
    if not _user_is_admin():
        flash("Only administrators can change detection rules.", "error")
        return redirect(url_for("detection_rules.detection_rule_list"))
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(url_for("detection_rules.detection_rule_list"))

    enabled_value = request.form.get("is_enabled")
    if enabled_value not in {"true", "false"}:
        flash("Please choose a valid rule state.", "error")
        return redirect(url_for("detection_rules.detection_rule_list"))

    try:
        changed = set_detection_rule_enabled(
            rule_id,
            enabled_value == "true",
            updated_by=session.get("user_id"),
        )
        flash(
            "Detection rule state updated." if changed else "Detection rule state was unchanged.",
            "success" if changed else "info",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("detection_rules.detection_rule_list"))


@detection_rules_bp.route(
    "/detection-rules/<int:rule_id>/edit",
    methods=["GET", "POST"],
)
@login_required
def detection_rule_edit(rule_id):
    if not _user_is_admin():
        flash("Only administrators can change detection rules.", "error")
        return redirect(url_for("detection_rules.detection_rule_list"))

    rule = get_detection_rule_by_id(rule_id)
    if rule is None:
        flash("Detection rule not found.", "error")
        return redirect(url_for("detection_rules.detection_rule_list"))

    if request.method == "POST":
        if not validate_csrf_token():
            flash("The security token is missing or invalid. Please retry.", "error")
            return redirect(url_for("detection_rules.detection_rule_list"))
        try:
            update_detection_rule(
                rule_id=rule_id,
                rule_name=request.form.get("rule_name"),
                description=request.form.get("description"),
                event_type=request.form.get("event_type"),
                severity=request.form.get("severity"),
                threshold=int(request.form.get("threshold", "")),
                window_minutes=int(request.form.get("window_minutes", "")),
                updated_by=session.get("user_id"),
            )
            flash("Detection rule updated successfully.", "success")
            return redirect(url_for("detection_rules.detection_rule_list"))
        except ValueError as error:
            flash(str(error), "error")

    return render_template(
        "detection_rule_form.html",
        rule=rule,
        severities=sorted(ALLOWED_RULE_SEVERITIES),
    )


@detection_rules_bp.route("/detection-alerts", methods=["GET"])
@login_required
def detection_alert_list():
    status = request.args.get("status")
    if status == "":
        status = None
    try:
        alerts = get_detection_alerts(status=status)
    except ValueError:
        status = None
        alerts = get_detection_alerts()
        flash("Invalid alert filter; showing all alerts.", "error")
    for alert in alerts:
        alert["history"] = get_detection_alert_history(alert["id"])

    return render_template(
        "detection_alerts.html",
        alerts=alerts,
        status_filter=status or "",
        alert_statuses=sorted(ALLOWED_ALERT_STATUSES),
    )


@detection_rules_bp.route(
    "/detection-alerts/<int:alert_id>/status",
    methods=["POST"],
)
@login_required
def detection_alert_status(alert_id):
    if not _user_is_admin():
        flash("Only administrators can update detection alerts.", "error")
        return redirect(url_for("detection_rules.detection_alert_list"))
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(url_for("detection_rules.detection_alert_list"))

    try:
        set_detection_alert_status(
            alert_id,
            request.form.get("status"),
            updated_by=session.get("user_id"),
        )
        flash("Detection alert status updated.", "success")
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("detection_rules.detection_alert_list"))
