const assert = require('node:assert/strict');
const { test } = require('node:test');
const express = require('express');
const { createOrdersRouter } = require('./orders');
const { issueToken, verifyToken } = require('../auth-token');

// Jane is user 2 and owns order 1; order 2 belongs to user 4.
const orders = [
  order(1, 2, 'Jane Cooper'),
  order(2, 4, 'Arjun Mehta'),
];

function order(id, userId, customerName) {
  return {
    id,
    order_number: `SF-${1000 + id}`,
    user_id: userId,
    customer_name: customerName,
    shipping_address: `${customerName} address`,
    items: [{ name: 'Wireless Charging Pad', quantity: 1, price: 24.5 }],
    total: '24.50',
    status: 'delivered',
    created_at: '2026-09-01T10:00:00Z',
  };
}

// Models only the WHERE clauses the router uses, so a test can tell which
// query ran and with what.
function demoDatabase() {
  const calls = [];
  return {
    calls,
    async query(text, values) {
      calls.push({ text, values });
      if (/WHERE user_id = \$1/.test(text)) {
        return { rows: orders.filter((o) => o.user_id === values[0]) };
      }
      if (/WHERE id = \$1 AND user_id = \$2/.test(text)) {
        return { rows: orders.filter((o) => o.id === values[0] && o.user_id === values[1]) };
      }
      return { rows: orders.filter((o) => o.id === values[0]) };
    },
  };
}

const tokenFor = (userId) => `Bearer ${issueToken({ id: userId, role: 'user' })}`;

async function get(router, path, userId, authorization) {
  const app = express();
  app.use('/api', router);
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  try {
    const auth = authorization || (userId ? tokenFor(userId) : null);
    const headers = auth ? { Authorization: auth } : {};
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, { headers });
    return { status: response.status, body: await response.json() };
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

async function post(router, path, userId, body) {
  const app = express();
  app.use(express.json());
  app.use('/api', router);
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (userId) headers.Authorization = tokenFor(userId);
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() };
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

test('orders require a logged-in caller', async () => {
  for (const path of ['/api/orders', '/api/orders/1', '/api/orders-secure/1']) {
    const response = await get(createOrdersRouter(demoDatabase()), path);
    assert.equal(response.status, 401, path);
  }
});

test('the order list is only the caller\'s own orders', async () => {
  const response = await get(createOrdersRouter(demoDatabase()), '/api/orders', 2);
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.orders.map((o) => o.id), [1]);
});

test('the vulnerable route returns another customer\'s order (BOLA)', async () => {
  const db = demoDatabase();
  const response = await get(createOrdersRouter(db), '/api/orders/2', 2);

  assert.equal(response.status, 200);
  assert.equal(response.body.order.customerName, 'Arjun Mehta');
  // Parameterized all the same: this is an authorization bug, not injection.
  assert.deepEqual(db.calls[0].values, [2]);
});

test('the secure route answers 404 for someone else\'s order', async () => {
  const db = demoDatabase();
  const router = createOrdersRouter(db);

  const own = await get(router, '/api/orders-secure/1', 2);
  assert.equal(own.status, 200);
  assert.equal(own.body.order.customerName, 'Jane Cooper');

  const other = await get(router, '/api/orders-secure/2', 2);
  assert.equal(other.status, 404);
  assert.deepEqual(db.calls.at(-1).values, [2, 2]);
});

test('non-numeric ids are not found rather than a database error', async () => {
  const db = demoDatabase();
  const response = await get(createOrdersRouter(db), '/api/orders/abc', 2);
  assert.equal(response.status, 404);
  assert.equal(db.calls.length, 0);
});

test('tokens must be signed: the old base64 id token is refused', async () => {
  const forged = `Bearer ${Buffer.from('4').toString('base64')}`;
  const response = await get(createOrdersRouter(demoDatabase()), '/api/orders', null, forged);
  assert.equal(response.status, 401);
});

test('responses name the owner, which the gateway ownership check reads', async () => {
  const response = await get(createOrdersRouter(demoDatabase()), '/api/orders/1', 2);
  assert.equal(response.body.order.userId, 2);
});

// Models the writes POST /api/orders makes: a sequence pull for the new id, an
// optional products lookup, and the insert itself.
function writableDatabase({ products = [] } = {}) {
  const calls = [];
  const inserted = [];
  let nextId = 100;
  return {
    calls,
    inserted,
    async query(text, values) {
      calls.push({ text, values });
      if (/nextval/.test(text)) {
        return { rows: [{ id: nextId++ }] };
      }
      if (/FROM products WHERE id = ANY/.test(text)) {
        const ids = values[0].map(String);
        return { rows: products.filter((p) => ids.includes(String(p.id))) };
      }
      if (/INSERT INTO orders/.test(text)) {
        const [id, orderNumber, userId, customerName, shippingAddress, items, total] = values;
        const row = {
          id,
          order_number: orderNumber,
          user_id: userId,
          customer_name: customerName,
          shipping_address: shippingAddress,
          items: JSON.parse(items),
          total,
          status: 'pending',
          created_at: '2026-09-17T00:00:00Z',
        };
        inserted.push(row);
        return { rows: [row] };
      }
      throw new Error(`unexpected query in POST /api/orders test: ${text}`);
    },
  };
}

test('POST /api/orders requires a logged-in caller', async () => {
  const response = await post(createOrdersRouter(writableDatabase()), '/api/orders', null, { items: [] });
  assert.equal(response.status, 401);
});

test('POST /api/orders places an order under the caller\'s own id', async () => {
  const db = writableDatabase();
  const response = await post(createOrdersRouter(db), '/api/orders', 2, {
    items: [{ productId: 'p1', name: 'Wireless Charging Pad', price: 24.5, quantity: 1 }],
    shippingAddress: { fullName: 'Jane Cooper', street: '12 Harbour Lane', city: 'Portsmouth', state: '', zip: 'PO1 3AB', country: 'UK' },
  });

  assert.equal(response.status, 201);
  assert.equal(response.body.order.userId, 2);
  assert.equal(response.body.order.total, 32.45);
  assert.equal(response.body.order.orderNumber, `SF-${db.inserted[0].id}`);
  assert.equal(response.body.order.items[0].name, 'Wireless Charging Pad');
});

test('POST /api/orders ignores a client-supplied price for a real product', async () => {
  const db = writableDatabase({ products: [{ id: 5, name: 'Real Product', price: '20.00' }] });
  const response = await post(createOrdersRouter(db), '/api/orders', 2, {
    items: [{ productId: '5', name: 'Fake name', price: 0.01, quantity: 1 }],
    shippingAddress: { fullName: 'Jane Cooper', street: '12 Harbour Lane', city: 'Portsmouth', zip: 'PO1 3AB', country: 'UK' },
  });

  assert.equal(response.status, 201);
  assert.equal(response.body.order.total, 27.59);
  assert.equal(response.body.order.items[0].name, 'Real Product');
  assert.equal(response.body.order.items[0].price, 20);
});

test('POST /api/orders rejects a bad quantity', async () => {
  const db = writableDatabase();
  for (const quantity of [0, 100, 1.5]) {
    const response = await post(createOrdersRouter(db), '/api/orders', 2, {
      items: [{ productId: 'p1', name: 'Item', price: 10, quantity }],
      shippingAddress: { fullName: 'Jane Cooper', street: 'x', city: 'y', zip: 'z', country: 'UK' },
    });
    assert.equal(response.status, 400, `quantity ${quantity}`);
  }
  assert.equal(db.inserted.length, 0);
});

test('POST /api/orders rejects an empty or oversized item list', async () => {
  const db = writableDatabase();
  const empty = await post(createOrdersRouter(db), '/api/orders', 2, { items: [], shippingAddress: {} });
  assert.equal(empty.status, 400);

  const tooMany = await post(createOrdersRouter(db), '/api/orders', 2, {
    items: Array.from({ length: 51 }, () => ({ productId: 'p1', quantity: 1 })),
    shippingAddress: {},
  });
  assert.equal(tooMany.status, 400);
});

test('verifyToken refuses tampered, re-signed and expired tokens', () => {
  const token = issueToken({ id: 2, role: 'user' });
  assert.equal(verifyToken(token).sub, '2');

  const [header, , signature] = token.split('.');
  const claims = Buffer.from(JSON.stringify({ sub: '4', exp: 4102444800 })).toString('base64url');
  assert.equal(verifyToken(`${header}.${claims}.${signature}`), null);
  assert.equal(verifyToken(issueToken({ id: 4 }, { key: 'someone-elses-secret' })), null);
  assert.equal(verifyToken(issueToken({ id: 2 }, { now: Date.now() - 2 * 60 * 60 * 1000 })), null);
});
