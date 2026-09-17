const fs = require('fs')
const path = require('path')
const { Pool } = require('pg')
const { PRODUCTS } = require('./data/products')
const { ORDERS } = require('./data/orders')

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
      role TEXT NOT NULL,
      name TEXT
    )
  `)
  // name did not exist before the BOLA demo; older databases created it NULL.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT`)

  // Names match the customers in data/orders.js, so a login shows the same
  // person whose orders it owns.
  const seedUsers = [
    { email: 'admin@shopforge.com', password: 'admin123', role: 'administrator', name: 'ShopForge Returns Desk' },
    { email: 'jane@example.com', password: 'user123', role: 'user', name: 'Jane Cooper' },
    { email: 'admin', password: 'adminPassword123', role: 'administrator', name: 'Priya Nair' },
    { email: 'user1', password: 'password1', role: 'user', name: 'Arjun Mehta' },
    { email: 'john_doe', password: 'doePassword', role: 'user', name: 'John Doe' }
  ]

  for (const user of seedUsers) {
    await pool.query(
      `INSERT INTO users (email, password, role, name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) DO UPDATE SET name = $4 WHERE users.name IS NULL`,
      [user.email, user.password, user.role, user.name]
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

  // Orders for the BOLA demo. order_number is unique so re-seeding is
  // idempotent, like products. The owner is resolved from the seeded users by
  // email, so ids stay consistent however the users table was numbered.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      order_number TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      customer_name TEXT NOT NULL,
      shipping_address TEXT NOT NULL,
      items JSONB NOT NULL,
      total NUMERIC(10,2) NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)

  for (const o of ORDERS) {
    await pool.query(
      `INSERT INTO orders (order_number, user_id, customer_name, shipping_address, items, total, status)
       SELECT $1, id, $2, $3, $4, $5, $6 FROM users WHERE email = $7
       ON CONFLICT (order_number) DO NOTHING`,
      [o.order_number, o.customer_name, o.shipping_address, JSON.stringify(o.items),
       o.total, o.status, o.customer_email]
    )
  }
}

module.exports = { pool, initDb }