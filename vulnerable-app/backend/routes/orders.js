const express = require('express');
const { pool } = require('../db');

// The caller, from "Authorization: Bearer <base64 user id>" -- the same token
// the storefront already makes after login (src/services/api.js makeToken).
// It is a demo token, not a credential: it identifies, it does not prove. That
// is enough to show what an ownership check is for.
function callerId(req) {
  const match = /^Bearer\s+(\S+)$/.exec(req.get('authorization') || '');
  if (!match) return null;
  const id = Number(Buffer.from(match[1], 'base64').toString('utf8'));
  return Number.isInteger(id) && id > 0 ? id : null;
}

function orderId(value) {
  return /^\d{1,9}$/.test(value) ? Number(value) : null;
}

const toOrder = (row) => ({
  id: row.id,
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
    const id = callerId(req);
    if (!id) {
      return res.status(401).json({ success: false, message: 'Log in to view orders' });
    }
    req.callerId = id;
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
  // Deliberately vulnerable to BOLA / IDOR. It checks that the caller is logged
  // in, and never that the order is theirs, so counting through ids returns
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

  return router;
}

const router = createOrdersRouter();

module.exports = router;
module.exports.createOrdersRouter = createOrdersRouter;
