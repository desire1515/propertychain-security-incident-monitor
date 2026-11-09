from flask import Blueprint, render_template, request

from backend.utils.security import login_required
from backend.services.event_service import get_security_events
from backend.services.incident_service import get_incidents

events_bp = Blueprint("events", __name__)


@events_bp.route("/events", methods=["GET"])
@login_required
def security_events():
    events = get_security_events(limit=500)
    linked_incidents = {
        incident["source_event_reference"]: incident["incident_reference"]
        for incident in get_incidents()
        if incident["source_event_reference"]
    }

    severity_filter = request.args.get("severity", "").lower()
    classification_filter = request.args.get("classification", "").upper()
    search_query = request.args.get("search", "").strip().lower()

    allowed_severities = {"", "low", "medium", "high", "critical"}
    allowed_classifications = {"", "REAL", "SIMULATED", "TEST"}

    if severity_filter not in allowed_severities:
        severity_filter = ""

    if classification_filter not in allowed_classifications:
        classification_filter = ""

    if severity_filter:
        events = [
            event for event in events
            if event["severity"] == severity_filter
        ]

    if classification_filter:
        events = [
            event for event in events
            if event["classification"] == classification_filter
        ]

    if search_query:
        events = [
            event for event in events
            if search_query in " ".join([
                event["event_reference"],
                event["source"],
                event["event_type"],
                event["description"]
            ]).lower()
        ]

    for event in events:
        event["incident_reference"] = linked_incidents.get(
            event["event_reference"]
        )

    return render_template(
        "events.html",
        events=events,
        severity_filter=severity_filter,
        classification_filter=classification_filter,
        search_query=search_query,
        total_events=len(events)
    )
