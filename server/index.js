const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const db = require('./db');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

const app = express();
const upload = multer();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const normalizeSeverity = (value) => {
  if (!value) return 'unknown';
  const severity = String(value).trim().toLowerCase();
  if (/(critical|urgent)/.test(severity)) return 'critical';
  if (/high/.test(severity)) return 'high';
  if (/medium|moderate/.test(severity)) return 'medium';
  if (/low|informational|info/.test(severity)) return 'low';
  return 'unknown';
};

const buildOCSF = (item, sourceType) => {
  const assetName = item['Asset'] || item.asset || item['Asset Name'] || item.asset_name || 'unknown-asset';
  const assetId = item['Asset ID'] || item.asset_id || item.asset || assetName;
  const vulnId = item['Vuln ID'] || item.vuln_id || item['Vulnerability ID'] || item.vulnerability_id || item.id || 'unknown-vuln';
  const title = item['Title'] || item.title || item['Name'] || item.name || 'Untitled finding';
  const description = item['Description'] || item.description || item['Details'] || item.details || 'No description provided';
  const category = item['Category'] || item.category || item['Type'] || item.type || 'vulnerability';
  const severity = normalizeSeverity(item['Severity'] || item.severity || item['Risk'] || item.risk);
  const remediation = item['Remediation'] || item.remediation || item['Fix'] || item.fix || 'Remediation action required.';
  const detectedAt = item['Detected At'] || item.detected_at || item['Timestamp'] || item.timestamp || new Date().toISOString();

  return {
    schema_version: '1.0',
    source: sourceType,
    asset: {
      id: assetId,
      name: assetName,
    },
    vulnerability: {
      id: vulnId,
      title,
      description,
      category,
      severity,
      remediation,
    },
    event: {
      detected_at: detectedAt,
      source: sourceType,
    },
  };
};

const insertFinding = async (ocsf, source) => {
  const severity = ocsf.vulnerability.severity || 'unknown';
  const assetName = ocsf.asset.name || 'unknown';
  const vulnerabilityId = ocsf.vulnerability.id || 'unknown';

  const insert = `
    INSERT INTO ocsf_findings (source, severity, asset_name, vulnerability_id, ocsf)
    VALUES ($1, $2, $3, $4, $5)
    RETURNING id;
  `;
  const result = await db.query(insert, [source, severity, assetName, vulnerabilityId, ocsf]);
  return result.rows[0];
};

const ingestItems = async (items, sourceType) => {
  if (!Array.isArray(items)) {
    throw new Error('Expected an array of report items.');
  }
  const inserted = [];
  for (const item of items) {
    const ocsf = buildOCSF(item, sourceType);
    const record = await insertFinding(ocsf, sourceType);
    inserted.push({ ...record, ocsf });
  }
  return inserted;
};

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/upload/csv', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'CSV file is required.' });
    }
    const content = req.file.buffer.toString('utf8');
    const records = parse(content, { columns: true, skip_empty_lines: true });
    const inserted = await ingestItems(records, 'csv');
    res.json({ imported: inserted.length, items: inserted });
  } catch (error) {
    console.error('CSV upload error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/upload/json', async (req, res) => {
  try {
    let items = req.body;
    if (items && items.items) items = items.items;
    if (typeof items === 'string') {
      items = JSON.parse(items);
    }
    const inserted = await ingestItems(items, 'json');
    res.json({ imported: inserted.length, items: inserted });
  } catch (error) {
    console.error('JSON upload error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/vulnerabilities', async (req, res) => {
  try {
    const result = await db.query('SELECT id, source, severity, asset_name, vulnerability_id, ocsf, created_at FROM ocsf_findings ORDER BY created_at DESC');
    res.json({ findings: result.rows });
  } catch (error) {
    console.error('Fetch findings error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/export/poam', async (req, res) => {
  try {
    const result = await db.query('SELECT id, source, severity, asset_name, vulnerability_id, ocsf, created_at FROM ocsf_findings ORDER BY severity DESC, created_at DESC');
    const actions = result.rows.map((row) => ({
      id: row.id,
      asset: row.ocsf.asset.name,
      asset_id: row.ocsf.asset.id,
      vulnerability_id: row.ocsf.vulnerability.id,
      title: row.ocsf.vulnerability.title,
      description: row.ocsf.vulnerability.description,
      severity: row.ocsf.vulnerability.severity,
      remediation: row.ocsf.vulnerability.remediation,
      source: row.source,
      created_at: row.created_at,
      status: 'Open',
      milestone: 'Validate and remediate within 30 days',
    }));

    const csv = stringify(actions, {
      header: true,
      columns: ['id', 'asset', 'asset_id', 'vulnerability_id', 'title', 'description', 'severity', 'remediation', 'source', 'created_at', 'status', 'milestone']
    });

    res.setHeader('Content-Disposition', 'attachment; filename="poam-report.csv"');
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  } catch (error) {
    console.error('POA&M export error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Vanquish server running on http://localhost:${PORT}`);
});
