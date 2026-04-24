const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require('@modelcontextprotocol/sdk/types.js');
const { Pool } = require('pg');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '../server/.env') });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/vanquish',
});

const db = (text, params) => pool.query(text, params);

const server = new Server(
  { name: 'vanquish', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'get_vulnerability_summary',
      description: 'Returns a summary of all vulnerabilities: total count, breakdown by severity (critical/high/medium/low/unknown), and how many match the CISA Known Exploited Vulnerabilities (KEV) catalog.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'list_vulnerabilities',
      description: 'List vulnerabilities with optional filters. Returns id, asset, severity, title, source, detector_id, cvss_score, detected_at, and whether it is in the KEV catalog.',
      inputSchema: {
        type: 'object',
        properties: {
          severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low', 'unknown'],
            description: 'Filter by severity level.',
          },
          asset: {
            type: 'string',
            description: 'Filter by asset name or IP (partial match).',
          },
          source: {
            type: 'string',
            enum: ['nessus', 'zap', 'twistlock', 'json'],
            description: 'Filter by scanner source.',
          },
          kev_only: {
            type: 'boolean',
            description: 'If true, return only findings that appear in the CISA KEV catalog.',
          },
          limit: {
            type: 'number',
            description: 'Maximum number of results (default 50, max 200).',
          },
          offset: {
            type: 'number',
            description: 'Pagination offset (default 0).',
          },
        },
      },
    },
    {
      name: 'get_vulnerability_detail',
      description: 'Get full details for a specific vulnerability finding by its database ID, including the complete OCSF event and any associated CVSS and KEV data.',
      inputSchema: {
        type: 'object',
        required: ['id'],
        properties: {
          id: { type: 'number', description: 'The vulnerability finding ID.' },
        },
      },
    },
    {
      name: 'search_vulnerabilities',
      description: 'Full-text search across vulnerability title, description, asset name, and vulnerability ID.',
      inputSchema: {
        type: 'object',
        required: ['query'],
        properties: {
          query: { type: 'string', description: 'Search term (e.g. "Log4j", "192.168.1.10", "CVE-2021").' },
          limit: { type: 'number', description: 'Maximum results (default 50).' },
        },
      },
    },
    {
      name: 'get_kev_catalog',
      description: 'List entries from the CISA Known Exploited Vulnerabilities catalog stored locally. Optionally filter by vendor/product.',
      inputSchema: {
        type: 'object',
        properties: {
          vendor: { type: 'string', description: 'Filter by vendor/project name (partial match).' },
          product: { type: 'string', description: 'Filter by product name (partial match).' },
          limit: { type: 'number', description: 'Maximum results (default 50).' },
        },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    if (name === 'get_vulnerability_summary') {
      const [total, bySev, kevCount] = await Promise.all([
        db('SELECT COUNT(*) FROM ocsf_findings'),
        db(`SELECT severity, COUNT(*) AS count
            FROM ocsf_findings
            GROUP BY severity
            ORDER BY CASE severity
              WHEN 'critical' THEN 1
              WHEN 'high'     THEN 2
              WHEN 'medium'   THEN 3
              WHEN 'low'      THEN 4
              ELSE 5 END`),
        db(`SELECT COUNT(DISTINCT f.id) AS count
            FROM ocsf_findings f
            JOIN kev k ON k.cve_id = f.vulnerability_id`),
      ]);

      const summary = {
        total: parseInt(total.rows[0].count, 10),
        by_severity: Object.fromEntries(bySev.rows.map(r => [r.severity, parseInt(r.count, 10)])),
        kev_matches: parseInt(kevCount.rows[0].count, 10),
      };

      return {
        content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }],
      };
    }

    if (name === 'list_vulnerabilities') {
      const limit = Math.min(args.limit ?? 50, 200);
      const offset = args.offset ?? 0;
      const conditions = [];
      const params = [];

      if (args.severity) {
        params.push(args.severity);
        conditions.push(`f.severity = $${params.length}`);
      }
      if (args.asset) {
        params.push(`%${args.asset}%`);
        conditions.push(`f.asset_name ILIKE $${params.length}`);
      }
      if (args.source) {
        params.push(args.source);
        conditions.push(`f.source = $${params.length}`);
      }
      if (args.kev_only) {
        conditions.push(`k.cve_id IS NOT NULL`);
      }

      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
      params.push(limit, offset);

      const result = await db(
        `SELECT
           f.id,
           f.asset_name,
           f.severity,
           f.source,
           f.vulnerability_id,
           f.ocsf->'vulnerability'->>'title' AS title,
           f.ocsf->'vulnerability'->>'detector_id' AS detector_id,
           f.ocsf->'event'->>'detected_at' AS detected_at,
           c.cvss_score,
           CASE WHEN k.cve_id IS NOT NULL THEN true ELSE false END AS in_kev
         FROM ocsf_findings f
         LEFT JOIN cvss c ON c.cve_id = f.vulnerability_id
         LEFT JOIN kev  k ON k.cve_id = f.vulnerability_id
         ${where}
         ORDER BY CASE f.severity
           WHEN 'critical' THEN 1
           WHEN 'high'     THEN 2
           WHEN 'medium'   THEN 3
           WHEN 'low'      THEN 4
           ELSE 5 END, f.id
         LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
      );

      return {
        content: [{ type: 'text', text: JSON.stringify(result.rows, null, 2) }],
      };
    }

    if (name === 'get_vulnerability_detail') {
      const result = await db(
        `SELECT
           f.*,
           c.cvss_score,
           c.cvss_vector,
           c.cvss_version,
           c.severity AS cvss_severity,
           k.vulnerability_name AS kev_name,
           k.date_added AS kev_date_added,
           k.required_action AS kev_required_action,
           k.due_date AS kev_due_date,
           k.known_ransomware_campaign_use
         FROM ocsf_findings f
         LEFT JOIN cvss c ON c.cve_id = f.vulnerability_id
         LEFT JOIN kev  k ON k.cve_id = f.vulnerability_id
         WHERE f.id = $1`,
        [args.id]
      );

      if (!result.rows.length) {
        return { content: [{ type: 'text', text: `No vulnerability found with id ${args.id}` }] };
      }

      return {
        content: [{ type: 'text', text: JSON.stringify(result.rows[0], null, 2) }],
      };
    }

    if (name === 'search_vulnerabilities') {
      const limit = Math.min(args.limit ?? 50, 200);
      const term = `%${args.query}%`;

      const result = await db(
        `SELECT
           f.id,
           f.asset_name,
           f.severity,
           f.source,
           f.vulnerability_id,
           f.ocsf->'vulnerability'->>'title' AS title,
           f.ocsf->'vulnerability'->>'description' AS description,
           c.cvss_score,
           CASE WHEN k.cve_id IS NOT NULL THEN true ELSE false END AS in_kev
         FROM ocsf_findings f
         LEFT JOIN cvss c ON c.cve_id = f.vulnerability_id
         LEFT JOIN kev  k ON k.cve_id = f.vulnerability_id
         WHERE
           f.asset_name ILIKE $1
           OR f.vulnerability_id ILIKE $1
           OR f.ocsf->>'vulnerability' ILIKE $1
         ORDER BY CASE f.severity
           WHEN 'critical' THEN 1
           WHEN 'high'     THEN 2
           WHEN 'medium'   THEN 3
           WHEN 'low'      THEN 4
           ELSE 5 END
         LIMIT $2`,
        [term, limit]
      );

      return {
        content: [{ type: 'text', text: JSON.stringify(result.rows, null, 2) }],
      };
    }

    if (name === 'get_kev_catalog') {
      const limit = Math.min(args.limit ?? 50, 200);
      const conditions = [];
      const params = [];

      if (args.vendor) {
        params.push(`%${args.vendor}%`);
        conditions.push(`vendor_project ILIKE $${params.length}`);
      }
      if (args.product) {
        params.push(`%${args.product}%`);
        conditions.push(`product ILIKE $${params.length}`);
      }

      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
      params.push(limit);

      const result = await db(
        `SELECT
           cve_id,
           vendor_project,
           product,
           vulnerability_name,
           date_added,
           short_description,
           required_action,
           due_date,
           known_ransomware_campaign_use
         FROM kev
         ${where}
         ORDER BY date_added DESC NULLS LAST
         LIMIT $${params.length}`,
        params
      );

      return {
        content: [{ type: 'text', text: JSON.stringify(result.rows, null, 2) }],
      };
    }

    return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Database error: ${err.message}` }],
      isError: true,
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err.message}\n`);
  process.exit(1);
});
