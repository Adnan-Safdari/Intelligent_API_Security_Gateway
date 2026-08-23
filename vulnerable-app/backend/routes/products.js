const express = require('express');
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

const selectProducts = `SELECT id, name, description, price, original_price, category, image,
                                stock, rating, num_reviews, is_new_arrival
                           FROM products`;

function createProductsRouter(db = pool) {
  const router = express.Router();

  // GET /api/products/search?q=<query>
  //
  // Deliberately unsafe, isolated SQLi demonstration route. This is the only
  // query in the demo backend that concatenates user input. It can alter which
  // rows from the demo products table are returned; it cannot reach the host,
  // filesystem, or any non-demo capability.
  router.get('/products/search', async (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q : '';
    const query = `${selectProducts} WHERE name ILIKE '%${q}%' ORDER BY id`;

    try {
      const result = await db.query(query);
      const products = result.rows.map(toCard);
      return res.status(200).json({ products, total: products.length });
    } catch (error) {
      console.error('Vulnerable product search query failed:', error);
      return res.status(500).json({ success: false, message: 'Product search failed' });
    }
  });

  // GET /api/products/search-secure?q=<query>
  // A comparison route for explaining why the preceding route is vulnerable.
  // The IASG demo still compares the vulnerable route direct versus proxied.
  router.get('/products/search-secure', async (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q : '';

    try {
      const result = await db.query(
        `${selectProducts} WHERE name ILIKE $1 ORDER BY id`,
        [`%${q}%`],
      );
      const products = result.rows.map(toCard);
      return res.status(200).json({ products, total: products.length });
    } catch (error) {
      console.error('Secure product search query failed:', error);
      return res.status(500).json({ success: false, message: 'Product search failed' });
    }
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
    const result = await db.query(
      `${selectProducts} ${where}
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
    const result = await db.query(
      `${selectProducts} WHERE id = $1 LIMIT 1`,
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

  return router;
}

const router = createProductsRouter();

module.exports = router;
module.exports.createProductsRouter = createProductsRouter;
