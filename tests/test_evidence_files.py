import hashlib
import io
import sqlite3
from pathlib import Path

import pytest

from backend.services.incident_service import (
    add_incident_evidence,
    create_incident,
    get_incident_by_reference,
    get_incident_evidence,
    get_incident_evidence_custody,
    verify_incident_evidence,
)


def _incident(user):
    reference = create_incident(
        title="Evidence upload test",
        description="A test incident for uploaded evidence.",
        severity="medium",
        classification="TEST",
        created_by=user["id"],
    )
    return get_incident_by_reference(reference)


def _session(client, user):
    with client.session_transaction() as session:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["csrf_token"] = "test-csrf-token"


def test_upload_hash_verification_and_custody_history(
    app,
    test_user,
):
    incident = _incident(test_user)
    content = b"timestamp,event\n2026-11-08,access denied\n"

    evidence_id = add_incident_evidence(
        incident["id"],
        "LOG",
        "Uploaded audit log excerpt.",
        collected_by=test_user["id"],
        file_stream=io.BytesIO(content),
        original_filename="audit.csv",
    )
    evidence = get_incident_evidence(incident["id"])[0]
    saved_file = (
        Path(app.config["DATABASE_PATH"]).parent
        / "private_evidence"
        / evidence["storage_path"]
    )

    assert evidence["id"] == evidence_id
    assert evidence["evidence_reference"].startswith("EVD-")
    assert evidence["original_filename"] == "audit.csv"
    assert evidence["file_size"] == len(content)
    assert evidence["mime_type"] == "text/csv"
    assert evidence["sha256_hash"] == hashlib.sha256(content).hexdigest()
    assert saved_file.read_bytes() == content
    assert "static" not in saved_file.parts
    assert [row["action"] for row in get_incident_evidence_custody(evidence_id)] == [
        "REGISTERED",
        "UPLOADED",
    ]

    result = verify_incident_evidence(evidence_id, test_user["id"])
    assert result == {
        "verified": True,
        "expected_sha256": evidence["sha256_hash"],
        "actual_sha256": evidence["sha256_hash"],
    }
    assert get_incident_evidence_custody(evidence_id)[-1]["action"] == "VERIFIED"

    saved_file.write_bytes(b"tampered")
    result = verify_incident_evidence(evidence_id, test_user["id"])
    assert result["verified"] is False
    assert result["actual_sha256"] != result["expected_sha256"]
    assert get_incident_evidence_custody(evidence_id)[-1]["action"] == (
        "INTEGRITY_MISMATCH"
    )


def test_uploaded_evidence_is_immutable_and_invalid_file_is_not_persisted(
    app,
    test_user,
    database,
):
    incident = _incident(test_user)
    with pytest.raises(ValueError, match="file type is not allowed"):
        add_incident_evidence(
            incident["id"],
            "DOCUMENT",
            "Rejected executable upload.",
            collected_by=test_user["id"],
            file_stream=io.BytesIO(b"not an executable"),
            original_filename="payload.exe",
        )

    assert database.execute(
        "SELECT COUNT(*) FROM incident_evidence"
    ).fetchone()[0] == 0

    evidence_id = add_incident_evidence(
        incident["id"],
        "LOG",
        "Immutable file evidence.",
        collected_by=test_user["id"],
        file_stream=io.BytesIO(b"immutable evidence"),
        original_filename="evidence.log",
    )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        database.execute(
            "UPDATE incident_evidence SET sha256_hash = 'forged' WHERE id = ?",
            (evidence_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        database.execute(
            "DELETE FROM incident_evidence_custody WHERE evidence_id = ?",
            (evidence_id,),
        )


def test_analyst_can_upload_download_and_verify_evidence_with_csrf(
    client,
    analyst,
    test_user,
):
    incident = _incident(test_user)
    _session(client, analyst)

    upload = client.post(
        f"/incidents/{incident['incident_reference']}/evidence",
        data={
            "evidence_type": "LOG",
            "description": "Uploaded by analyst.",
            "csrf_token": "test-csrf-token",
            "evidence_file": (io.BytesIO(b"analyst evidence"), "capture.txt"),
        },
        follow_redirects=True,
    )
    assert upload.status_code == 200
    assert b"Evidence file uploaded and recorded." in upload.data

    evidence = get_incident_evidence(incident["id"])[0]
    download = client.get(
        f"/incidents/evidence/{evidence['id']}/download"
    )
    assert download.status_code == 200
    assert download.data == b"analyst evidence"
    assert "attachment" in download.headers["Content-Disposition"]
    assert download.headers["Cache-Control"] == "private, no-store"
    download.close()
    assert get_incident_evidence_custody(evidence["id"])[-1]["action"] == (
        "ACCESSED"
    )

    verify = client.post(
        f"/incidents/evidence/{evidence['id']}/verify",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=True,
    )
    assert verify.status_code == 200
    assert b"Evidence integrity verified." in verify.data


def test_evidence_download_requires_authentication_and_verify_requires_csrf(
    client,
    authenticated_client,
    test_user,
    database,
):
    incident = _incident(test_user)
    evidence_id = add_incident_evidence(
        incident["id"],
        "LOG",
        "Evidence for route access test.",
        collected_by=test_user["id"],
        file_stream=io.BytesIO(b"protected"),
        original_filename="protected.txt",
    )
    anonymous_client = client.application.test_client()
    anonymous_response = anonymous_client.get(
        f"/incidents/evidence/{evidence_id}/download"
    )
    assert anonymous_response.status_code == 401
    anonymous_response.close()

    before = database.execute(
        "SELECT COUNT(*) FROM incident_evidence_custody"
    ).fetchone()[0]
    response = authenticated_client.post(
        f"/incidents/evidence/{evidence_id}/verify",
        data={},
    )
    assert response.status_code == 302
    assert database.execute(
        "SELECT COUNT(*) FROM incident_evidence_custody"
    ).fetchone()[0] == before


def test_old_style_evidence_migration_adds_file_fields_without_losing_record(app):
    path = Path(app.config["DATABASE_PATH"])
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("DROP TABLE incident_evidence")
    connection.execute(
        """
        CREATE TABLE incident_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,
            description TEXT,
            evidence_data TEXT,
            collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        INSERT INTO incident_evidence (
            incident_id, evidence_type, description, evidence_data
        )
        VALUES (1, 'LOG', 'Legacy evidence', 'legacy://reference')
        """
    )
    connection.commit()
    connection.close()

    from database.db import migrate_database_schema

    migrate_database_schema()
    migrate_database_schema()
    connection = sqlite3.connect(path)
    try:
        columns = {
            row[1] for row in connection.execute(
                "PRAGMA table_info(incident_evidence)"
            )
        }
        row = connection.execute(
            """
            SELECT evidence_type, description, evidence_data, sha256_hash
            FROM incident_evidence WHERE id = 1
            """
        ).fetchone()
        assert {
            "evidence_reference",
            "original_filename",
            "storage_path",
            "file_size",
            "mime_type",
            "sha256_hash",
        } <= columns
        assert row == ("LOG", "Legacy evidence", "legacy://reference", None)
    finally:
        connection.close()
