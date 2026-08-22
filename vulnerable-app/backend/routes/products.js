const express = require('express');
const router = express.Router();
const { pool } = require('../db');

// Reshape a products row into the shape the storefront's ProductCard reads:
// an images array, camelCase originalPrice / numReviews / isNewArrival, and
// numbers rather than the strings pg returns for NUMERIC columns.
const toCard = (row) => ({
  _id: String(row.id),
  name: row.name,
  description: row.description,
  price: Number(row.price),
  originalPrice: row.original_price == null ? null : Number(row.original_price),
  category: row.category,
  images: row.image ? [row.image] : [],
  stock: row.stock,
  rating: Number(row.rating),
  numReviews: row.num_reviews,
  isNewArrival: row.is_new_arrival,
});

// GET /api/products
// Lists every product. Optional ?category= and ?search= narrow the list; with
// no query it returns the whole catalog, which is what /products asks for.
router.get('/products', async (req, res) => {
  const { category, search } = req.query;

  const clauses = [];
  const values = [];
  if (category) {
    values.push(category);
    clauses.push(`category = $${values.length}`);
  }
  if (search) {
    values.push(`%${search}%`);
    clauses.push(`(name ILIKE $${values.length} OR description ILIKE $${values.length})`);
  }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

  try {
    const result = await pool.query(
      `SELECT id, name, description, price, original_price, category, image,
              stock, rating, num_reviews, is_new_arrival
         FROM products ${where}
        ORDER BY id`,
      values
    );
    const products = result.rows.map(toCard);
    return res.status(200).json({ products, total: products.length });
  } catch (error) {
    console.error('Products query failed:', error);
    return res.status(500).json({ success: false, message: 'Failed to list products' });
  }
});

// GET /api/products/:id
router.get('/products/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, description, price, original_price, category, image,
              stock, rating, num_reviews, is_new_arrival
         FROM products WHERE id = $1 LIMIT 1`,
      [req.params.id]
    );
    if (!result.rows[0]) {
      return res.status(404).json({ success: false, message: 'Product not found' });
    }
    return res.status(200).json({ product: toCard(result.rows[0]) });
  } catch (error) {
    console.error('Product query failed:', error);
    return res.status(500).json({ success: false, message: 'Failed to fetch product' });
  }
});

module.exports = router;
