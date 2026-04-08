const fs = require('fs')
const path = require('path')
const { Pool } = require('pg')

const loadLocalEnvFile = () => {
  if (process.env.PGHOST || process.env.DB_HOST) {
    return
  }

  const envPath = path.join(__dirname, '.env')
  if (!fs.existsSync(envPath)) {
    return
  }

  const envFile = fs.readFileSync(envPath, 'utf8')
  for (const line of envFile.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue

    const separatorIndex = trimmed.indexOf('=')
    if (separatorIndex === -1) continue

    const key = trimmed.slice(0, separatorIndex).trim()
    const value = trimmed.slice(separatorIndex + 1).trim().replace(/^['"]|['"]$/g, '')
    if (!process.env[key]) {
      process.env[key] = value
    }
  }
}

loadLocalEnvFile()

const pool = new Pool({
  host: process.env.PGHOST || process.env.DB_HOST || 'localhost',
  port: Number(process.env.PGPORT || process.env.DB_PORT || 5432),
  user: process.env.PGUSER || process.env.DB_USER || 'postgres',
  password: process.env.PGPASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.PGDATABASE || process.env.DB_NAME || 'postgres'
})

const initDb = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )
  `)

  const seedUsers = [
    { email: 'admin@shopforge.com', password: 'admin123', role: 'administrator' },
    { email: 'jane@example.com', password: 'user123', role: 'user' },
    { email: 'admin', password: 'adminPassword123', role: 'administrator' },
    { email: 'user1', password: 'password1', role: 'user' },
    { email: 'john_doe', password: 'doePassword', role: 'user' }
  ]

  for (const user of seedUsers) {
    await pool.query(
      `INSERT INTO users (email, password, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (email) DO NOTHING`,
      [user.email, user.password, user.role]
    )
  }
}

module.exports = { pool, initDb }