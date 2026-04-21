CREATE TABLE IF NOT EXISTS executions (
  execution_id  TEXT PRIMARY KEY,
  lang          TEXT NOT NULL,
  exit_code     INTEGER,
  duration_ms   BIGINT,
  outcome       TEXT NOT NULL,
  stdout_bytes  INTEGER,
  stderr_bytes  INTEGER,
  error_msg     TEXT,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE executions ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'completed';

CREATE TABLE IF NOT EXISTS approval_ticket_uses (
  ticket_id            TEXT PRIMARY KEY,
  nonce                TEXT NOT NULL UNIQUE,
  execution_id         TEXT NOT NULL,
  policy_digest        TEXT NOT NULL,
  action_type          TEXT NOT NULL,
  resource_digest      TEXT NOT NULL,
  resource_digest_algo TEXT NOT NULL,
  consumed_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS side_effect_leases (
  lease_id              TEXT PRIMARY KEY,
  execution_id          TEXT NOT NULL UNIQUE,
  issuer                TEXT NOT NULL,
  issuer_key_id         TEXT NOT NULL,
  issued_at             TIMESTAMPTZ NOT NULL,
  expires_at            TIMESTAMPTZ NOT NULL,
  workload_kind         TEXT NOT NULL,
  workload_boot_digest  TEXT NOT NULL,
  workload_rootfs_image TEXT NOT NULL,
  policy_digest         TEXT NOT NULL,
  authority_digest      TEXT NOT NULL,
  envelope_json         JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS side_effect_lease_grants (
  lease_id              TEXT NOT NULL REFERENCES side_effect_leases(lease_id) ON DELETE CASCADE,
  grant_id              TEXT NOT NULL,
  action_kind           TEXT NOT NULL,
  selector_kind         TEXT NOT NULL,
  selector_digest       TEXT NOT NULL,
  selector_digest_algo  TEXT NOT NULL,
  selector_json         JSONB NOT NULL,
  budget_kind           TEXT NOT NULL,
  limit_count           BIGINT NOT NULL CHECK (limit_count >= 0),
  remaining_count       BIGINT NOT NULL CHECK (remaining_count >= 0),
  PRIMARY KEY (lease_id, grant_id)
);

CREATE INDEX IF NOT EXISTS idx_side_effect_lease_grants_lookup
  ON side_effect_lease_grants (lease_id, action_kind, selector_digest);
