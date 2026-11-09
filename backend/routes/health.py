from datetime import datetime, timezone

from flask import Blueprint, jsonify

health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "application": "PCSIRM",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200
