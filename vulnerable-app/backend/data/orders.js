// Orders for the BOLA (object-level authorization) demo. Every name, address
// and item is fictional.
//
// Owners are interleaved so the ids of any one customer's orders are scattered
// (jane owns 1, 6, 11, ...). That is how real order tables look, and it is what
// makes counting through ids reach other people's orders.

const CUSTOMERS = [
  { email: 'jane@example.com', name: 'Jane Cooper', address: '12 Harbour Lane, Portsmouth PO1 3AB' },
  { email: 'user1', name: 'Arjun Mehta', address: '48 MG Road, Bengaluru 560001' },
  { email: 'john_doe', name: 'John Doe', address: '221 Elm Street, Springfield IL 62701' },
  { email: 'admin@shopforge.com', name: 'ShopForge Returns Desk', address: '1 Commerce Way, Leeds LS1 4AP' },
  { email: 'admin', name: 'Priya Nair', address: '9 Lake View Apartments, Kochi 682011' },
];

const ITEMS = [
  { name: 'Mechanical Keyboard - RGB Backlit', price: 89.99 },
  { name: 'Wireless Charging Pad', price: 24.5 },
  { name: 'Ceramic Pour-Over Coffee Set', price: 42 },
  { name: 'Noise-Cancelling Headphones', price: 149 },
  { name: 'Standing Desk Mat', price: 35.25 },
];

const STATUSES = ['delivered', 'shipped', 'processing', 'delivered', 'cancelled'];

const ORDERS = Array.from({ length: 40 }, (_, i) => {
  const customer = CUSTOMERS[i % CUSTOMERS.length];
  const first = ITEMS[i % ITEMS.length];
  const second = ITEMS[(i * 3 + 1) % ITEMS.length];
  const items = [
    { name: first.name, quantity: 1, price: first.price },
    ...(i % 2 === 0 ? [{ name: second.name, quantity: 2, price: second.price }] : []),
  ];
  const total = items.reduce((sum, item) => sum + item.quantity * item.price, 0);
  return {
    order_number: `SF-${1001 + i}`,
    customer_email: customer.email,
    customer_name: customer.name,
    shipping_address: customer.address,
    items,
    total: Math.round(total * 100) / 100,
    status: STATUSES[i % STATUSES.length],
  };
});

module.exports = { ORDERS };
