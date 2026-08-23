const assert = require('node:assert/strict');
const { test } = require('node:test');
const express = require('express');
const demoResourcesRouter = require('./demo-resources');

async function get(pathname) {
  const app = express();
  app.use('/', demoResourcesRouter);
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });

  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${pathname}`);
    return { status: response.status, body: await response.json() };
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

test('planted enumeration resource contains only harmless demo data', async () => {
  const response = await get('/.env-demo');

  assert.equal(response.status, 200);
  assert.equal(response.body.demo, true);
  assert.match(response.body.message, /no environment values/i);
});

test('relative traversal can reach only a fake fixture within demo-files', async () => {
  const response = await get('/api/demo-files?file=public%2F..%2Ffake-secret.txt');

  assert.equal(response.status, 200);
  assert.equal(response.body.demo, true);
  assert.match(response.body.content, /not-a-real-secret/);
});

test('demo file route cannot escape its isolated directory', async () => {
  const response = await get('/api/demo-files?file=..%2F..%2Fpackage.json');

  assert.equal(response.status, 404);
  assert.match(response.body.message, /outside the isolated demo directory/i);
});
