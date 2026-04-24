const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { parse } = require('csv-parse/sync');
const { stringify } = require('csv-stringify/sync');
const db = require('./db');
const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js');
require('dotenv').config();

const app = express();
const upload = multer();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

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
  const assetName = item['Asset'] || item.asset || item['Asset Name'] || item.asset_name || item['Host'] || item.host || 'unknown-asset';
  const assetId = item['Asset ID'] || item.asset_id || item.asset || assetName;
  const vulnId = item['CVE'] || item.cve || item['Vuln ID'] || item.vuln_id || item['Vulnerability ID'] || item.vulnerability_id || item.id || 'unknown-vuln';
  const title = item['Title'] || item.title || item['Name'] || item.name || 'Untitled finding';
  const description = item['Description'] || item.description || item['Details'] || item.details || 'No description provided';
  const category = item['Category'] || item.category || item['Type'] || item.type || item['Plugin Family'] || item.plugin_family || 'vulnerability';
  const severity = normalizeSeverity(item['Severity'] || item.severity || item['Risk'] || item.risk || item['CVSS']);
  const remediation = item['Remediation'] || item.remediation || item['Solution'] || item.solution || item['Fix'] || item.fix || 'Remediation action required.';
  const detectedAt = item['Detected At'] || item.detected_at || item['Timestamp'] || item.timestamp || new Date().toISOString();

  let detectorId = '';
  if (sourceType === 'nessus') {
    detectorId = item['Plugin ID'] || item.plugin_id || '';
  } else if (sourceType === 'twistlock') {
    detectorId = item['CVE'] || item.cve || '';
  } else if (sourceType === 'zap') {
    detectorId = item['CWE'] || item.cwe || '';
  }

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
      detector_id: detectorId,
    },
    event: {
      detected_at: detectedAt,
      source: sourceType,
    },
  };
};

const insertFinding = async (ocsf, sourceType) => {
  const result = await db.query(
    `INSERT INTO ocsf_findings (source, severity, asset_name, vulnerability_id, ocsf)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (source, asset_name, vulnerability_id) DO UPDATE SET
       severity = EXCLUDED.severity,
       ocsf     = EXCLUDED.ocsf
     RETURNING id, source, severity, asset_name, vulnerability_id, ocsf, created_at`,
    [
      sourceType,
      String(ocsf?.vulnerability?.severity || 'unknown').toLowerCase(),
      ocsf?.asset?.name || 'unknown-asset',
      ocsf?.vulnerability?.id || 'unknown-vuln',
      ocsf,
    ]
  );
  return result.rows[0];
};

const insertKev = async (item) => {
  const cveId = item.cveID || item.cveId || item.CVE || item.cve_id;
  if (!cveId) return null;

  const result = await db.query(
    `INSERT INTO kev (
      cve_id,
      vendor_project,
      product,
      vulnerability_name,
      date_added,
      short_description,
      required_action,
      due_date,
      known_ransomware_campaign_use,
      notes,
      raw
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    ON CONFLICT (cve_id) DO UPDATE SET
      vendor_project = EXCLUDED.vendor_project,
      product = EXCLUDED.product,
      vulnerability_name = EXCLUDED.vulnerability_name,
      date_added = EXCLUDED.date_added,
      short_description = EXCLUDED.short_description,
      required_action = EXCLUDED.required_action,
      due_date = EXCLUDED.due_date,
      known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
      notes = EXCLUDED.notes,
      raw = EXCLUDED.raw
    RETURNING *`,
    [
      cveId,
      item.vendorProject || '',
      item.product || '',
      item.vulnerabilityName || '',
      item.dateAdded || null,
      item.shortDescription || '',
      item.requiredAction || '',
      item.dueDate || null,
      item.knownRansomwareCampaignUse || '',
      item.notes || '',
      item,
    ]
  );

  return result.rows[0];
};

const insertCvss = async (cveId, cvssScore, cvssVector, severity, cvssVersion) => {
  const insert = `
    INSERT INTO cvss (cve_id, cvss_score, cvss_vector, severity, cvss_version)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (cve_id) DO UPDATE SET
      cvss_score = EXCLUDED.cvss_score,
      cvss_vector = EXCLUDED.cvss_vector,
      severity = EXCLUDED.severity,
      cvss_version = EXCLUDED.cvss_version;
  `;
  await db.query(insert, [cveId, cvssScore, cvssVector, severity, cvssVersion || '3.1']);
};

const fetchCvssFromNist = async (cveId) => {
  const apiKey = process.env.NIST_KEY;
  if (!apiKey) {
    throw new Error('NIST_KEY not set');
  }
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
  const response = await fetch(url, { headers: { 'apiKey': apiKey } });
  if (!response.ok) {
    throw new Error(`NIST API error: ${response.status}`);
  }
  const data = await response.json();
  const vulnerabilities = data.vulnerabilities;
  if (!vulnerabilities || vulnerabilities.length === 0) return null;
  const metrics = vulnerabilities[0].cve.metrics;
  if (!metrics) return null;

  // Prefer CVSS v3.1, then v3.0, then v2.0
  if (metrics.cvssMetricV31?.length > 0) {
    const cvss = metrics.cvssMetricV31[0].cvssData;
    return { score: cvss.baseScore, vector: cvss.vectorString, severity: cvss.baseSeverity, version: '3.1' };
  }
  if (metrics.cvssMetricV30?.length > 0) {
    const cvss = metrics.cvssMetricV30[0].cvssData;
    return { score: cvss.baseScore, vector: cvss.vectorString, severity: cvss.baseSeverity, version: '3.0' };
  }
  if (metrics.cvssMetricV2?.length > 0) {
    const cvss = metrics.cvssMetricV2[0].cvssData;
    return { score: cvss.baseScore, vector: cvss.vectorString, severity: metrics.cvssMetricV2[0].baseSeverity, version: '2.0' };
  }
  return null;
};

const populateCvss = async () => {
  const result = await db.query('SELECT cve_id FROM kev');
  const cves = result.rows;
  let populated = 0;
  for (const { cve_id } of cves) {
    try {
      const cvssData = await fetchCvssFromNist(cve_id);
      if (cvssData) {
        await insertCvss(cve_id, cvssData.score, cvssData.vector, cvssData.severity, cvssData.version);
        populated++;
      }
    } catch (error) {
      console.error(`Error fetching CVSS for ${cve_id}:`, error);
    }
  }
  return populated;
};

const ingestKev = async (items) => {
  if (!Array.isArray(items)) {
    throw new Error('Expected an array of KEV items.');
  }
  const inserted = [];
  for (const item of items) {
    const record = await insertKev(item);
    if (record) inserted.push(record);
  }
  return inserted;
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

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin') {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.post('/api/populate/cvss', async (req, res) => {
  try {
    const populated = await populateCvss();
    res.json({ populated });
  } catch (error) {
    console.error('Populate CVSS error:', error);
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

app.post('/api/upload/csv', upload.single('file'), async (req, res) => {
  try {
    const csvData = req.file.buffer.toString('utf8');
    const items = parse(csvData, { columns: true, skip_empty_lines: true });
    const inserted = await ingestItems(items, 'nessus');
    res.json({ imported: inserted.length, items: inserted });
  } catch (error) {
    console.error('CSV upload error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/upload/kev', upload.single('file'), async (req, res) => {
  try {
    const csvData = req.file.buffer.toString('utf8');
    const items = parse(csvData, { columns: true, skip_empty_lines: true });
    const inserted = await ingestKev(items);
    res.json({ imported: inserted.length, items: inserted });
  } catch (error) {
    console.error('KEV upload error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/ingest/kev', async (req, res) => {
  try {
    const response = await fetch('https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv');
    if (!response.ok) {
      throw new Error(`Failed to download KEV file: ${response.status}`);
    }

    const csvData = await response.text();
    const items = parse(csvData, { columns: true, skip_empty_lines: true });
    const inserted = await ingestKev(items);
    res.json({ imported: inserted.length, items: inserted });
  } catch (error) {
    console.error('KEV ingest error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/upload/xml', upload.single('file'), async (req, res) => {
  try {
    const xmlData = req.file.buffer.toString('utf8');
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlData);
    let items = [];
    if (result.NessusClientData_v2 && result.NessusClientData_v2.Report) {
      const report = result.NessusClientData_v2.Report[0];
      if (report.ReportHost) {
        for (const host of report.ReportHost) {
          const assetName = host.$.name;
          if (host.ReportItem) {
            for (const item of host.ReportItem) {
              items.push({
                'Asset': assetName,
                'Plugin ID': item.$.pluginID,
                'Title': item.$.pluginName,
                'Description': item.description ? item.description[0] : '',
                'Severity': item.$.severity,
                'Category': item.$.pluginFamily,
                'Remediation': item.solution ? item.solution[0] : '',
              });
            }
          }
        }
      }
    }
    const inserted = await ingestItems(items, 'nessus');
    res.json({ imported: inserted.length, items: inserted });
  } catch (error) {
    console.error('XML upload error:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/vulnerabilities', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT f.id, f.source, f.severity, f.asset_name, f.vulnerability_id, f.ocsf, f.created_at,
             c.cvss_score, c.cvss_vector, c.cvss_version
      FROM ocsf_findings f
      LEFT JOIN cvss c ON c.cve_id = f.vulnerability_id
      ORDER BY f.created_at DESC
    `);
    res.json({ findings: result.rows });
  } catch (error) {
    console.error('Fetch findings error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/export/poam', async (req, res) => {
  try {
    const result = await db.query('SELECT id, source, severity, asset_name, vulnerability_id, ocsf, created_at FROM ocsf_findings ORDER BY severity DESC, created_at DESC');
    const actions = result.rows.map((row) => {
      const scheduledCompletion = new Date();
      scheduledCompletion.setDate(scheduledCompletion.getDate() + 30); // 30 days from now

      return {
        'POA&M ID': row.id,
        'Control Identifier': row.ocsf.vulnerability.category || 'Unknown',
        'Weakness Name': row.ocsf.vulnerability.title,
        'Weakness Description': row.ocsf.vulnerability.description,
        'Weakness Detector Source Identifier': row.ocsf.vulnerability.detector_id || 'N/A',
        'Weakness Source Identifier': row.source,
        'Status': 'Open',
        'Resources Required': 'TBD',
        'Scheduled Completion Date': scheduledCompletion.toISOString().split('T')[0],
        'Milestones with Completion Dates': row.ocsf.vulnerability.remediation + ' - Due: ' + scheduledCompletion.toISOString().split('T')[0],
        'Risk Rating': row.ocsf.vulnerability.severity.toUpperCase(),
        'Asset': row.ocsf.asset.name,
        'Vulnerability ID': row.ocsf.vulnerability.id,
        'Created At': row.created_at.toISOString().split('T')[0],
      };
    });

    const csv = stringify(actions, {
      header: true,
      columns: [
        'POA&M ID',
        'Control Identifier',
        'Weakness Name',
        'Weakness Description',
        'Weakness Detector Source Identifier',
        'Weakness Source Identifier',
        'Status',
        'Resources Required',
        'Scheduled Completion Date',
        'Milestones with Completion Dates',
        'Risk Rating',
        'Asset',
        'Vulnerability ID',
        'Created At',
      ]
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
