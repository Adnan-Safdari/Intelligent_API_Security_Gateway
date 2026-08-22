const fs = require('fs')
const path = require('path')
const { Pool } = require('pg')
const { PRODUCTS } = require('./data/products')

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

  // Products for the storefront. name is unique so re-seeding is idempotent,
  // the same way the user seed is keyed on email.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      price NUMERIC(10,2) NOT NULL,
      original_price NUMERIC(10,2),
      category TEXT NOT NULL DEFAULT '',
      image TEXT NOT NULL DEFAULT '',
      stock INTEGER NOT NULL DEFAULT 0,
      rating NUMERIC(2,1) NOT NULL DEFAULT 0,
      num_reviews INTEGER NOT NULL DEFAULT 0,
      is_new_arrival BOOLEAN NOT NULL DEFAULT FALSE
    )
  `)

  for (const p of PRODUCTS) {
    await pool.query(
      `INSERT INTO products
         (name, description, price, original_price, category, image, stock, rating, num_reviews, is_new_arrival)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (name) DO NOTHING`,
      [p.name, p.description, p.price, p.original_price, p.category, p.image,
       p.stock, p.rating, p.num_reviews, p.is_new_arrival]
    )
  }
}

module.exports = { pool, initDb }