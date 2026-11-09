from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from backend.services.settings_service import (
    ALLOWED_USER_ROLES,
    change_user_password,
    create_managed_analyst,
    get_managed_users,
    get_user_profile,
    update_managed_user,
)
from backend.utils.security import login_required, validate_csrf_token

settings_bp = Blueprint("settings", __name__)


def _require_admin():
    if session.get("role") != "admin":
        abort(403)


@settings_bp.route("/settings", methods=["GET"])
@login_required
def settings_page():
    profile = get_user_profile(session.get("user_id"))
    admin = profile["role"] == "admin"
    users = get_managed_users(profile["id"]) if admin else []
    return render_template(
        "settings.html",
        profile=profile,
        users=users,
        roles=sorted(ALLOWED_USER_ROLES),
        system_info={
            "application": "PropertyChain Security Incident Response and Monitoring",
            "version": "Not defined",
            "database": "SQLite",
            "environment": "Testing" if current_app.config.get("TESTING") else "Development",
            "firebase": "Planned; no verified Firebase adapter is active.",
            "blockchain": "Planned; no verified Ethereum adapter is active.",
        },
    )


@settings_bp.route("/settings/password", methods=["POST"])
@login_required
def update_password():
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(url_for("settings.settings_page"))
    try:
        change_user_password(
            session.get("user_id"),
            request.form.get("current_password"),
            request.form.get("new_password"),
        )
        flash("Password changed successfully.", "success")
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("settings.settings_page"))


@settings_bp.route("/settings/users", methods=["POST"])
@login_required
def create_analyst_account():
    _require_admin()
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(url_for("settings.settings_page"))
    try:
        create_managed_analyst(
            request.form.get("username"),
            request.form.get("password"),
            session.get("user_id"),
        )
        flash("Analyst account created successfully.", "success")
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("settings.settings_page"))


@settings_bp.route("/settings/users/<int:user_id>", methods=["POST"])
@login_required
def update_user_account(user_id):
    _require_admin()
    if not validate_csrf_token():
        flash("The security token is missing or invalid. Please retry.", "error")
        return redirect(url_for("settings.settings_page"))

    role = request.form.get("role")
    active_value = request.form.get("is_active")
    if active_value not in {"0", "1"}:
        flash("Invalid account status.", "error")
        return redirect(url_for("settings.settings_page"))
    try:
        changed = update_managed_user(
            user_id,
            role=role,
            is_active=active_value == "1",
            updated_by=session.get("user_id"),
        )
        flash(
            "User account updated." if changed else "User account was unchanged.",
            "success" if changed else "info",
        )
    except ValueError as error:
        flash(str(error), "error")
    return redirect(url_for("settings.settings_page"))
