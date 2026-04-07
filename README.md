# Vanquish

A React frontend and Express backend for ingesting vulnerability reports from CSV and JSON, storing them in OCSF format in PostgreSQL, and exporting a POA&M report.

## Structure

- `server/` — Express API, PostgreSQL ingestion, OCSF normalization, POA&M export
- `client/` — React + Vite user interface for uploading reports and viewing findings
- `sample_files/` — example import files

## Setup

1. Copy environment file and update database URL:

   ```bash
   cp server/.env.example server/.env
   ```

2. Install dependencies:

   ```bash
   npm run install-all
   ```

3. Create the PostgreSQL database and schema:

   ```bash
   npm run setup-db
   ```

4. Start both applications:

   ```bash
   npm run dev
   ```

5. Open the React app at `http://localhost:5173`.

### Using Docker for PostgreSQL

If you prefer to run PostgreSQL with Docker, start the database service with:

```bash
docker compose up -d
```

This creates a Postgres container using the default connection:

- `POSTGRES_USER=postgres`
- `POSTGRES_PASSWORD=postgres`
- `POSTGRES_DB=vanquish`

The server already uses `postgres://postgres:postgres@localhost:5432/vanquish` by default, so no further configuration is required if you keep the `.env` settings in `server/.env`.

pgAdmin is also included for database administration at `http://localhost:5050` (login: `admin@vanquish.local` / `admin`).

The full stack can be run with Docker Compose:

- Server: `http://localhost:4000`
- Client: `http://localhost:3000`
- pgAdmin: `http://localhost:5050`

## Backend API

- `POST /api/upload/csv` — upload a CSV file with vulnerability rows
- `POST /api/upload/json` — upload JSON payload or array of findings
- `GET /api/vulnerabilities` — fetch stored OCSF findings
- `GET /api/export/poam` — download a POA&M export CSV file

## Notes

- The backend stores every finding as a JSONB OCSF payload in PostgreSQL.
- The frontend allows CSV or JSON ingestion and POA&M export.
