
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_reference TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    classification TEXT NOT NULL,
    description TEXT NOT NULL,
    source_timestamp TEXT,
    received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    raw_data TEXT
);

CREATE TABLE IF NOT EXISTS monitoring_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'inactive',
    description TEXT,
    monitoring_mode TEXT NOT NULL DEFAULT 'PLANNED',
    connection_status TEXT NOT NULL DEFAULT 'NOT_CONNECTED',
    is_enabled INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    last_successful_check TEXT,
    last_error TEXT,
    created_by INTEGER,
    updated_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    description TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    threshold INTEGER NOT NULL DEFAULT 1,
    window_minutes INTEGER NOT NULL DEFAULT 60,
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detection_rule_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    matched INTEGER NOT NULL DEFAULT 0,
    matching_count INTEGER NOT NULL DEFAULT 0,
    executed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(id),
    FOREIGN KEY (event_id) REFERENCES security_events(id)
);

CREATE TABLE IF NOT EXISTS detection_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (rule_id) REFERENCES detection_rules(id),
    FOREIGN KEY (event_id) REFERENCES security_events(id),
    UNIQUE (rule_id, event_id)
);

CREATE TABLE IF NOT EXISTS detection_alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    changed_by INTEGER,
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES detection_alerts(id),
    FOREIGN KEY (changed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS monitoring_ingestion_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER,
    status TEXT NOT NULL,
    events_seen INTEGER NOT NULL DEFAULT 0,
    events_ingested INTEGER NOT NULL DEFAULT 0,
    duplicates_skipped INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT,
    started_by INTEGER,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    FOREIGN KEY (source_id) REFERENCES monitoring_sources(id),
    FOREIGN KEY (started_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS monitoring_ingested_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL,
    external_reference TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_id) REFERENCES monitoring_sources(id),
    FOREIGN KEY (event_id) REFERENCES security_events(id),
    UNIQUE (source_id, external_reference),
    UNIQUE (event_id)
);

CREATE TABLE IF NOT EXISTS simulation_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'completed',
    events_generated INTEGER NOT NULL DEFAULT 0,
    executed_by INTEGER,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_reference TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    classification TEXT NOT NULL,
    assigned_to INTEGER,
    source_event_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (source_event_id) REFERENCES security_events(id)
);

CREATE TABLE IF NOT EXISTS incident_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,
    description TEXT,
    evidence_data TEXT,
    collected_by INTEGER,
    collected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    evidence_reference TEXT,
    original_filename TEXT,
    storage_path TEXT,
    file_size INTEGER,
    mime_type TEXT,
    sha256_hash TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS incident_evidence_custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor_id INTEGER,
    details TEXT,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES incident_evidence(id),
    FOREIGN KEY (actor_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS incident_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    description TEXT NOT NULL,
    action_status TEXT NOT NULL DEFAULT 'proposed',
    performed_by INTEGER,
    updated_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (performed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    activity TEXT NOT NULL,
    details TEXT,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE TABLE IF NOT EXISTS system_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_source_event
ON incidents(source_event_id)
WHERE source_event_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_detection_alert_history_alert
ON detection_alert_history(alert_id, changed_at);

CREATE INDEX IF NOT EXISTS idx_monitoring_ingestion_jobs_source
ON monitoring_ingestion_jobs(source_id, started_at);

CREATE INDEX IF NOT EXISTS idx_monitoring_ingested_events_event
ON monitoring_ingested_events(event_id);

CREATE INDEX IF NOT EXISTS idx_incident_evidence_custody_evidence
ON incident_evidence_custody(evidence_id, recorded_at);

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_no_update
BEFORE UPDATE ON incident_evidence
BEGIN
    SELECT RAISE(ABORT, 'Evidence records are immutable.');
END;

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_no_delete
BEFORE DELETE ON incident_evidence
BEGIN
    SELECT RAISE(ABORT, 'Evidence records are immutable.');
END;

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_custody_no_update
BEFORE UPDATE ON incident_evidence_custody
BEGIN
    SELECT RAISE(ABORT, 'Evidence custody records are append-only.');
END;

CREATE TRIGGER IF NOT EXISTS trg_incident_evidence_custody_no_delete
BEFORE DELETE ON incident_evidence_custody
BEGIN
    SELECT RAISE(ABORT, 'Evidence custody records are append-only.');
END;
