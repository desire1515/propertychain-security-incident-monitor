from flask import (
    Blueprint,
    jsonify,
    request,
    session,
    render_template,
    redirect,
    url_for
)

from backend.services.auth_service import authenticate_user, record_logout
from backend.utils.security import (
    get_csrf_token,
    login_required,
    validate_csrf_token,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/signin", methods=["GET", "POST"])
def browser_login():
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("dashboard.dashboard"))

        get_csrf_token()
        return render_template("login.html")

    if not validate_csrf_token():
        return render_template(
            "login.html",
            error="The security token is missing or invalid. Please retry.",
        ), 400

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return render_template(
            "login.html",
            error="Please enter valid login details."
        ), 400

    user = authenticate_user(username, password)

    if user is None:
        return render_template(
            "login.html",
            error="Invalid username or password."
        ), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    get_csrf_token()

    return redirect(url_for("dashboard.dashboard"))


@auth_bp.route("/login", methods=["POST"])
def login():
    if not validate_csrf_token():
        return jsonify({"error": "The security token is missing or invalid."}), 400

    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid login details."}), 400

    user = authenticate_user(username, password)

    if user is None:
        return jsonify({"error": "Invalid username or password."}), 401

    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    csrf_token = get_csrf_token()

    return jsonify({
        "message": "Login successful.",
        "user": user,
        "csrf_token": csrf_token,
    }), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf_token():
        if request.is_json:
            return jsonify({"error": "The security token is missing or invalid."}), 400
        return "The security token is missing or invalid.", 400

    record_logout(session.get("user_id"))
    session.clear()

    if request.is_json:
        return jsonify({"message": "Logout successful."}), 200

    return redirect(url_for("auth.browser_login"))


@auth_bp.route("/me", methods=["GET"])
@login_required
def current_user():
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 401

    return jsonify({
        "authenticated": True,
        "user": {
            "id": session["user_id"],
            "username": session["username"],
            "role": session["role"]
        }
    }), 200
