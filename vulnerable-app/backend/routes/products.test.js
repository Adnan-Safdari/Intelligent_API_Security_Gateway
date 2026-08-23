const assert = require('node:assert/strict');
const { test } = require('node:test');
const express = require('express');
const { createProductsRouter } = require('./products');

const rows = [
  row(1, 'Mechanical Keyboard - RGB Backlit'),
  row(2, 'Wireless Charging Pad'),
  row(3, 'Ceramic Pour-Over Coffee Set'),
];

function row(id, name) {
  return {
    id,
    name,
    description: `${name} description`,
    price: '10.00',
    original_price: null,
    category: 'Demo',
    image: '',
    stock: 10,
    rating: '4.0',
    num_reviews: 1,
    is_new_arrival: false,
  };
}

function demoDatabase() {
  const calls = [];
  return {
    calls,
    async query(text, values) {
      calls.push({ text, values });

      // This adapter models the relevant PostgreSQL LIKE semantics. The test
      // makes the route's deliberate concatenation observable without needing
      // a shared database process for every unit-test run.
      if (text.includes("' OR 1=1 --")) return { rows };
      const pattern = values?.[0] || text.match(/ILIKE '%(.*)%'/)?.[1] || '';
      const needle = pattern.replace(/^%|%$/g, '').toLowerCase();
      return { rows: rows.filter((product) => product.name.toLowerCase().includes(needle)) };
    },
  };
}

async function get(router, path) {
  const app = express();
  app.use('/api', router);
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`);
    return { status: response.status, body: await response.json() };
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

test('normal vulnerable search returns its matching product subset', async () => {
  const db = demoDatabase();
  const response = await get(createProductsRouter(db), '/api/products/search?q=keyboard');

  assert.equal(response.status, 200);
  assert.equal(response.body.total, 1);
  assert.equal(response.body.products[0].name, 'Mechanical Keyboard - RGB Backlit');
  assert.match(db.calls[0].text, /ILIKE '%keyboard%'/);
  assert.equal(db.calls[0].values, undefined);
});

test('SQLi payload changes the vulnerable product search query semantics', async () => {
  const db = demoDatabase();
  const response = await get(
    createProductsRouter(db),
    `/api/products/search?q=${encodeURIComponent("' OR 1=1 --")}`,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.total, rows.length);
  assert.match(db.calls[0].text, /WHERE name ILIKE '%' OR 1=1 --%'/);
  assert.equal(db.calls[0].values, undefined);
});

test('secure comparison search keeps the SQLi payload as a parameter', async () => {
  const db = demoDatabase();
  const response = await get(
    createProductsRouter(db),
    `/api/products/search-secure?q=${encodeURIComponent("' OR 1=1 --")}`,
  );

  assert.equal(response.status, 200);
  assert.equal(response.body.total, 0);
  assert.match(db.calls[0].text, /ILIKE \$1/);
  assert.deepEqual(db.calls[0].values, ["%' OR 1=1 --%"]);
});
