CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS ocsf_findings (
  id SERIAL PRIMARY KEY,
  report_id UUID DEFAULT gen_random_uuid(),
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  asset_name TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  ocsf JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
