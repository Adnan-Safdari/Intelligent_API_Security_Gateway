const express = require('express');
const { pool } = require('../db');
const { callerFrom } = require('../auth-token');

function orderId(value) {
  return /^\d{1,9}$/.test(value) ? Number(value) : null;
}

// userId is in the response the way most real APIs include it. It is also what
// lets the gateway's ownership check (routes.ownership) see whose order this is.
const toOrder = (row) => ({
  id: row.id,
  userId: row.user_id,
  orderNumber: row.order_number,
  customerName: row.customer_name,
  shippingAddress: row.shipping_address,
  items: row.items,
  total: Number(row.total),
  status: row.status,
  createdAt: row.created_at,
});

const selectOrders = `SELECT id, order_number, user_id, customer_name, shipping_address,
                             items, total, status, created_at
                        FROM orders`;

function createOrdersRouter(db = pool) {
  const router = express.Router();

  const requireCaller = (req, res, next) => {
    const caller = callerFrom(req);
    if (!caller) {
      return res.status(401).json({ success: false, message: 'Log in to view orders' });
    }
    req.callerId = caller.id;
    return next();
  };

  // GET /api/orders
  //
  // The caller's own orders -- ordinary use, and how a real client learns which
  // ids are theirs.
  router.get('/orders', requireCaller, async (req, res) => {
    try {
      const result = await db.query(`${selectOrders} WHERE user_id = $1 ORDER BY id`, [req.callerId]);
      return res.status(200).json({ orders: result.rows.map(toOrder) });
    } catch (error) {
      console.error('Order list query failed:', error);
      return res.status(500).json({ success: false, message: 'Failed to list orders' });
    }
  });

  // GET /api/orders/:id
  //
  // Deliberately vulnerable to BOLA / IDOR. It verifies the caller's token, and
  // never checks that the order is theirs, so counting through ids returns
  // other customers' names, addresses and purchases. The SQL is parameterized:
  // this is an authorization bug, not an injection one.
  router.get('/orders/:id', requireCaller, async (req, res) => {
    const id = orderId(req.params.id);
    if (!id) return res.status(404).json({ success: false, message: 'Order not found' });
    try {
      const result = await db.query(`${selectOrders} WHERE id = $1 LIMIT 1`, [id]);
      if (!result.rows[0]) {
        return res.status(404).json({ success: false, message: 'Order not found' });
      }
      return res.status(200).json({ order: toOrder(result.rows[0]) });
    } catch (error) {
      console.error('Vulnerable order query failed:', error);
      return res.status(500).json({ success: false, message: 'Failed to fetch order' });
    }
  });

  // GET /api/orders-secure/:id
  //
  // The comparison route: the ownership check is part of the query. Someone
  // else's order answers 404, the same as one that does not exist, so the
  // response does not even confirm which ids are real.
  router.get('/orders-secure/:id', requireCaller, async (req, res) => {
    const id = orderId(req.params.id);
    if (!id) return res.status(404).json({ success: false, message: 'Order not found' });
    try {
      const result = await db.query(
        `${selectOrders} WHERE id = $1 AND user_id = $2 LIMIT 1`,
        [id, req.callerId],
      );
      if (!result.rows[0]) {
        return res.status(404).json({ success: false, message: 'Order not found' });
      }
      return res.status(200).json({ order: toOrder(result.rows[0]) });
    } catch (error) {
      console.error('Secure order query failed:', error);
      return res.status(500).json({ success: false, message: 'Failed to fetch order' });
    }
  });

  // POST /api/orders
  //
  // Checkout, for real: the order is stored under the caller's id, so it
  // immediately shows up in their own GET /api/orders and is a genuine target
  // for the BOLA route above. A client-supplied price is only trusted for
  // catalogue ids that are not in the products table (the storefront's mock
  // products, which never reach this backend); a real product's price and
  // name are always looked up server-side.
  router.post('/orders', requireCaller, async (req, res) => {
    const { items, shippingAddress } = req.body || {};

    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      return res.status(400).json({ success: false, message: 'An order needs 1 to 50 items' });
    }

    const normalizedItems = [];
    for (const raw of items) {
      const quantity = Number(raw && raw.quantity);
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 99) {
        return res.status(400).json({ success: false, message: 'Each item needs a quantity between 1 and 99' });
      }
      normalizedItems.push({
        productId: raw && raw.productId != null ? String(raw.productId) : null,
        name: raw && typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : 'Item',
        price: Math.max(0, Number(raw && raw.price) || 0),
        quantity,
        image: raw && typeof raw.image === 'string' ? raw.image : null,
      });
    }

    const numericIds = normalizedItems
      .map((item) => item.productId)
      .filter((id) => id && /^\d+$/.test(id))
      .map(Number);

    try {
      if (numericIds.length > 0) {
        const products = await db.query(`SELECT id, name, price FROM products WHERE id = ANY($1)`, [numericIds]);
        const byId = new Map(products.rows.map((row) => [String(row.id), row]));
        for (const item of normalizedItems) {
          const product = item.productId && byId.get(item.productId);
          if (product) {
            item.name = product.name;
            item.price = Number(product.price);
          }
        }
      }

      const address = shippingAddress && typeof shippingAddress === 'object' ? shippingAddress : {};
      const customerName = typeof address.fullName === 'string' && address.fullName.trim()
        ? address.fullName.trim()
        : 'Customer';
      const addressLine = [address.street, address.city, address.state, address.zip, address.country]
        .filter((part) => typeof part === 'string' && part.trim())
        .join(', ') || 'No address provided';

      const subtotal = normalizedItems.reduce((sum, item) => sum + item.price * item.quantity, 0);
      const shippingPrice = subtotal >= 50 ? 0 : 5.99;
      const taxPrice = Math.round(subtotal * 0.08 * 100) / 100;
      const total = Math.round((subtotal + shippingPrice + taxPrice) * 100) / 100;

      // id is picked up front from the same sequence the id column defaults
      // to, so order_number can embed it in the same insert instead of a
      // second write once the row exists.
      const sequence = await db.query(`SELECT nextval(pg_get_serial_sequence('orders', 'id')) AS id`);
      const id = Number(sequence.rows[0].id);
      const orderNumber = `SF-${id}`;

      const inserted = await db.query(
        `INSERT INTO orders (id, order_number, user_id, customer_name, shipping_address, items, total, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
         RETURNING id, order_number, user_id, customer_name, shipping_address, items, total, status, created_at`,
        [id, orderNumber, req.callerId, customerName, addressLine, JSON.stringify(normalizedItems), total],
      );
      return res.status(201).json({ order: toOrder(inserted.rows[0]) });
    } catch (error) {
      console.error('Order creation failed:', error);
      return res.status(500).json({ success: false, message: 'Failed to place order' });
    }
  });

  return router;
}

const router = createOrdersRouter();

module.exports = router;
module.exports.createOrdersRouter = createOrdersRouter;
