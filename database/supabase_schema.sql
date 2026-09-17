-- ========================================================
-- CYBERTRACE - SUPABASE POSTGRESQL SCHEMA
-- Digital Forensics Time Machine Database Definition
-- ========================================================

-- Enable UUID extension if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. SECURITY_EVENTS TABLE
-- Stores every ingested log record with computed anomaly metrics and risk analysis
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp VARCHAR(50) NOT NULL,
    "user" VARCHAR(100) NOT NULL,
    device VARCHAR(100) NOT NULL,
    ip VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    file VARCHAR(255) DEFAULT '',
    data_size INTEGER DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    severity VARCHAR(20) DEFAULT 'LOW',
    reason TEXT DEFAULT '',
    is_anomaly BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. INCIDENTS TABLE
-- Groups correlated suspicious security events into actionable forensic cases
CREATE TABLE IF NOT EXISTS incidents (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    start_time VARCHAR(50) NOT NULL,
    end_time VARCHAR(50) NOT NULL,
    risk_score INTEGER DEFAULT 0,
    severity VARCHAR(20) DEFAULT 'LOW',
    summary TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. EVIDENCE TABLE
-- Tracks entity relationships (User -> Device -> IP -> File -> Action) discovered during investigation
CREATE TABLE IF NOT EXISTS evidence (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(50) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    entity_type VARCHAR(50) NOT NULL,       -- 'USER', 'DEVICE', 'IP', 'FILE', 'TRANSFER'
    entity_value VARCHAR(255) NOT NULL,     -- e.g. 'Rahul', '185.23.45.10', 'passwords.txt'
    related_entity VARCHAR(255) NOT NULL,   -- e.g. 'DEV01'
    relationship VARCHAR(100) NOT NULL,     -- e.g. 'OPERATED_ON', 'ACCESSED_FROM', 'READ_FILE'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. INVESTIGATION_REPORTS TABLE
-- Stores full forensic synthesis, AI reasoning, timeline reconstruction, and executive summary
CREATE TABLE IF NOT EXISTS investigation_reports (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(50) REFERENCES incidents(incident_id) ON DELETE CASCADE,
    summary TEXT,
    timeline JSONB,                         -- Structured event sequence
    evidence_summary TEXT,
    ai_explanation TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indices for rapid querying during time machine playback and filtering
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_risk_score ON security_events(risk_score);
CREATE INDEX IF NOT EXISTS idx_events_user ON security_events("user");
CREATE INDEX IF NOT EXISTS idx_incidents_id ON incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
