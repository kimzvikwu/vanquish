const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

const connectionString = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/vanquish';
const pool = new Pool({ connectionString });

module.exports = {
  query: (text, params) => pool.query(text, params),
};
