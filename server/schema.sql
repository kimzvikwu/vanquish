CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS cvss (
  id SERIAL PRIMARY KEY,
  cve_id TEXT UNIQUE NOT NULL,
  cvss_score TEXT,
  cvss_vector TEXT,
  severity TEXT,
  cvss_version TEXT DEFAULT '3.1',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ocsf_findings (
  id SERIAL PRIMARY KEY,
  report_id UUID DEFAULT gen_random_uuid(),
  source TEXT NOT NULL,
  severity TEXT NOT NULL,
  asset_name TEXT NOT NULL,
  vulnerability_id TEXT NOT NULL,
  ocsf JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (source, asset_name, vulnerability_id)
);

CREATE TABLE IF NOT EXISTS kev (
  id SERIAL PRIMARY KEY,
  cve_id TEXT UNIQUE NOT NULL,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added DATE,
  short_description TEXT,
  required_action TEXT,
  due_date DATE,
  known_ransomware_campaign_use TEXT,
  notes TEXT,
  raw JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
