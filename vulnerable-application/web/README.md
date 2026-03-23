# ShopForge — Frontend Only

A complete e-commerce frontend built with **React + Vite**.  
Works entirely in the browser with a mock API — no backend required.

---

## Quick Start

```bash
npm install
npm run dev
```

Open **http://localhost:5173**

---

## Demo Accounts

| Email | Password | Role |
|---|---|---|
| `jane@example.com` | `user123` | Customer |
| `admin@shopforge.com` | `admin123` | Admin |

---

## Folder Structure

```
src/
├── services/
│   ├── api.js          ← ALL API calls live here (swap for real backend)
│   └── mockData.js     ← 15 sample products, 2 users, 2 orders
├── context/
│   ├── AuthContext.jsx
│   ├── CartContext.jsx
│   └── WishlistContext.jsx
├── components/
│   ├── common/         ProductCard, Pagination, ProtectedRoute
│   └── layout/         Navbar, Footer
├── pages/
│   ├── Home.jsx        Hero, featured products, categories
│   ├── Shop.jsx        Grid, filters, sort, pagination
│   ├── ProductPage.jsx Images, reviews, add to cart
│   ├── Cart.jsx        Qty selector, totals
│   ├── Checkout.jsx    Address + mock payment form
│   ├── Auth.jsx        Login / Register
│   ├── Orders.jsx      Order history + detail
│   ├── Wishlist.jsx    Saved products
│   └── Admin.jsx       Dashboard, CRUD products, orders, users
├── hooks/index.js
├── utils/index.js
└── styles/index.css
```

---

## Connecting a Real Backend

All API calls are in **`src/services/api.js`**.  
Each function has a comment showing its real REST endpoint, e.g.:

```js
// Real: GET /api/products
getAll: async (params) => { ... }

// Real: POST /api/users/login  
login: async ({ email, password }) => { ... }
```

To switch to a real backend:

1. `npm install axios`
2. Replace `api.js` with the axios version:

```js
import axios from 'axios'
const api = axios.create({ baseURL: 'http://localhost:5000/api' })

export const productApi = {
  getAll: (params) => api.get('/products', { params }).then(r => r.data),
  getById: (id) => api.get(`/products/${id}`).then(r => r.data),
  // ...
}
```

---

## Features

- ✅ Product grid with search, filters (category, price, rating), sort
- ✅ Pagination
- ✅ Product detail with image gallery and reviews
- ✅ Cart (persisted to localStorage)
- ✅ Wishlist (per-user, in-memory)
- ✅ Checkout with address + mock card/PayPal/COD
- ✅ Order history and detail view
- ✅ Login / Register with JWT-style token (base64 mock)
- ✅ Admin panel: stats, product CRUD, order status, user list
- ✅ Skeleton loaders, toast notifications, error states
- ✅ Fully responsive
