from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from backend.services.simulation_service import (
    SIMULATION_SCENARIOS,
    get_simulation_runs,
    run_simulation,
)
from backend.utils.security import login_required, validate_csrf_token

simulations_bp = Blueprint("simulations", __name__)


@simulations_bp.route("/simulations", methods=["GET", "POST"])
@login_required
def simulation_list():
    if request.method == "POST":
        if session.get("role") != "admin":
            flash("Only administrators can run simulations.", "error")
            return redirect(url_for("simulations.simulation_list"))
        if not validate_csrf_token():
            flash("The security token is missing or invalid. Please retry.", "error")
            return redirect(url_for("simulations.simulation_list"))
        try:
            result = run_simulation(
                request.form.get("scenario"),
                executed_by=session.get("user_id"),
            )
            flash(
                f"Simulation completed: {result['events_generated']} simulated event(s) generated.",
                "success",
            )
        except ValueError as error:
            flash(str(error), "error")
        return redirect(url_for("simulations.simulation_list"))

    return render_template(
        "simulations.html",
        scenarios=SIMULATION_SCENARIOS,
        runs=get_simulation_runs(),
    )
