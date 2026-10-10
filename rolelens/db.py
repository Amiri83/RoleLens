"""SQLite storage: schema and connection helpers."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- AWS accounts RoleLens can collect from. Secrets are Fernet-encrypted (crypto.SecretBox);
-- memory-only credentials are never written here.
CREATE TABLE IF NOT EXISTS accounts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    display_name      TEXT NOT NULL DEFAULT '',
    region            TEXT NOT NULL,
    auth_mode         TEXT NOT NULL,          -- env | profile | keys | temporary
    profile           TEXT NOT NULL DEFAULT '',
    access_key_id     TEXT NOT NULL DEFAULT '',
    secret_enc        TEXT,                   -- encrypted secret access key
    session_token_enc TEXT,                   -- encrypted session token (temporary)
    expires_at        TEXT,                   -- ISO UTC expiry of temporary credentials
    memory_only       INTEGER NOT NULL DEFAULT 0,
    aws_account_id    TEXT,                   -- AWS account id of the first successful connect
    last_seen_account_id TEXT                 -- AWS account id of the latest successful connect
);

-- One IAM collection. account_ref is the RoleLens account record (accounts.id);
-- account_id is the AWS account id.
CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at     TEXT NOT NULL,
    account_ref  INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
    account_id   TEXT,
    account_name TEXT,              -- account display name, frozen at capture time
    status       TEXT NOT NULL,     -- running | ok | failed
    error        TEXT,
    warnings     TEXT NOT NULL DEFAULT '[]'   -- JSON list
);
CREATE INDEX IF NOT EXISTS ix_snapshots_account ON snapshots(account_ref);

-- iam:ListRoles + iam:GetRole. trust_doc is the decoded AssumeRolePolicyDocument (JSON).
CREATE TABLE IF NOT EXISTS roles (
    snapshot_id          INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    role_name            TEXT NOT NULL,
    role_id              TEXT NOT NULL DEFAULT '',
    arn                  TEXT NOT NULL DEFAULT '',
    path                 TEXT NOT NULL DEFAULT '/',
    description          TEXT NOT NULL DEFAULT '',
    create_date          TEXT NOT NULL DEFAULT '',
    max_session_duration INTEGER NOT NULL DEFAULT 3600,
    permissions_boundary TEXT NOT NULL DEFAULT '',  -- policy ARN ('' if none)
    last_used_at         TEXT NOT NULL DEFAULT '',  -- RoleLastUsed.LastUsedDate ('' never)
    last_used_region     TEXT NOT NULL DEFAULT '',
    trust_doc            TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (snapshot_id, role_name)
);

-- Policies of a role. kind: inline (iam:ListRolePolicies + GetRolePolicy, document set)
-- | managed (iam:ListAttachedRolePolicies; document in managed_policies).
CREATE TABLE IF NOT EXISTS role_policies (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    role_name   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    policy_arn  TEXT NOT NULL DEFAULT '',
    document    TEXT,               -- inline policy document (JSON)
    PRIMARY KEY (snapshot_id, role_name, kind, policy_name)
);

-- iam:GetPolicy + iam:GetPolicyVersion (default version) of every attached managed policy.
CREATE TABLE IF NOT EXISTS managed_policies (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    arn             TEXT NOT NULL,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '/',
    default_version TEXT NOT NULL DEFAULT '',
    aws_managed     INTEGER NOT NULL DEFAULT 0,
    document        TEXT,           -- NULL when it could not be read
    PRIMARY KEY (snapshot_id, arn)
);

-- Local drafts cloned from a collected role. Never written to AWS. original / model are JSON
-- role models (see drafts.py): original is frozen at clone time for the diff.
CREATE TABLE IF NOT EXISTS drafts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_ref INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
    snapshot_id INTEGER,            -- snapshot the role was cloned from (may be deleted later)
    source_role TEXT NOT NULL,
    original    TEXT NOT NULL,
    model       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- Background jobs (jobs.py): written when a job starts and ends, so a reloaded page can
-- re-attach to it and show the outcome. messages / log: JSON lists (no secrets: result
-- lines and the first line of each log record only).
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    account_ref INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL,      -- running | done | cancelled | error
    step        TEXT NOT NULL DEFAULT '',
    done        INTEGER NOT NULL DEFAULT 0,
    total       INTEGER NOT NULL DEFAULT 0,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    elapsed     INTEGER NOT NULL DEFAULT 0,
    error       TEXT NOT NULL DEFAULT '',
    messages    TEXT NOT NULL DEFAULT '[]',
    log         TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_jobs_account ON jobs(account_ref, started_at);
"""

# Seconds a connection waits for another thread's write lock before failing.
BUSY_TIMEOUT = 30.0
ACTIVE_ACCOUNT_KEY = "active_account"


def connect(db_path: Path | str) -> sqlite3.Connection:
    """A new connection. Connections are never shared between threads: every request
    and every background job thread opens its own."""
    conn = sqlite3.connect(str(db_path), detect_types=0, timeout=BUSY_TIMEOUT)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path | str) -> None:
    with closing(db_path) as conn:
        # WAL: readers (page requests) are not blocked while a background job writes.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)


@contextmanager
def closing(db_path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a connection, commit on success, roll back on error, always close."""
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
