const db = require('./db');
require('dotenv').config();

async function run() {
  console.log('Step 1: removing duplicate findings (keeping earliest per source/asset/vuln)...');
  const del = await db.query(`
    DELETE FROM ocsf_findings
    WHERE id NOT IN (
      SELECT DISTINCT ON (source, asset_name, vulnerability_id) id
      FROM ocsf_findings
      ORDER BY source, asset_name, vulnerability_id, created_at ASC
    )
  `);
  console.log(`  Removed ${del.rowCount} duplicate rows.`);

  console.log('Step 2: adding unique constraint...');
  await db.query(`
    ALTER TABLE ocsf_findings
    ADD CONSTRAINT ocsf_findings_source_asset_vuln_key
    UNIQUE (source, asset_name, vulnerability_id)
  `);
  console.log('  Constraint added.');

  const { rows } = await db.query('SELECT COUNT(*) FROM ocsf_findings');
  console.log(`Done. ${rows[0].count} findings remain.`);
  process.exit(0);
}

run().catch(err => {
  if (err.code === '42710') {
    console.log('Constraint already exists — nothing to do.');
    process.exit(0);
  }
  console.error('Migration failed:', err.message);
  process.exit(1);
});
