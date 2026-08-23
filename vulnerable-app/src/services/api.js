/**
 * api.js — Mock API layer
 *
 * Mirrors the real REST API surface exactly.
 * Swap this file for the real axios version when a backend is ready.
 * Real backend endpoints are documented in comments next to each function.
 */

import { MOCK_PRODUCTS, MOCK_USERS, MOCK_ORDERS } from './mockData'

// ─── In-memory state (simulates a database) ───────────────────────────────────
let products = MOCK_PRODUCTS.map((p) => ({ ...p }))
let users = MOCK_USERS.map((u) => ({ ...u }))
let orders = MOCK_ORDERS.map((o) => ({ ...o }))
let nextOrderId = 1000

// ─── Helpers ──────────────────────────────────────────────────────────────────
const delay = (ms = 350) => new Promise((r) => setTimeout(r, ms))

const ENV_API_MODE = (import.meta.env.VITE_API_MODE || 'backend').toLowerCase()
const BACKEND_API_URL = import.meta.env.VITE_BACKEND_API_URL || 'http://localhost:5002'
const GATEWAY_API_URL = import.meta.env.VITE_GATEWAY_API_URL || 'http://localhost:8082'

const getApiMode = () => {
  const stored = localStorage.getItem('api_mode')
  return (stored || ENV_API_MODE) === 'gateway' ? 'gateway' : 'backend'
}

const getApiBaseUrl = () => {
  const mode = getApiMode()
  return mode === 'gateway'
    ? GATEWAY_API_URL
    : BACKEND_API_URL
}

const err = (msg, status = 400) => {
  const e = new Error(msg)
  e.status = status
  throw e
}

const getCurrentUser = () => {
  const token = localStorage.getItem('sf_token')
  if (!token) return null
  try {
    const id = atob(token)
    return users.find((u) => u._id === id) || null
  } catch { return null }
}

const makeToken = (id) => btoa(id)

// ─── Product API ──────────────────────────────────────────────────────────────
// Real: GET /api/products
export const productApi = {
  // Fetches the whole catalogue from the real backend (GET /api/products),
  // through the gateway or straight to the API depending on the API mode. This
  // is the one product call that leaves the browser; the rest below are still
  // the in-memory mock. If the backend is unreachable it falls back to the mock
  // so the storefront stays usable offline, the same way login does.
  getAllProducts: async (params = {}) => {
    const qs = new URLSearchParams()
    if (params.category) qs.set('category', params.category)
    if (params.search) qs.set('search', params.search)
    const suffix = qs.toString() ? `?${qs}` : ''

    try {
      const res = await fetch(`${getApiBaseUrl()}/api/products${suffix}`)
      if (!res.ok) throw new Error(`products request failed: ${res.status}`)
      const data = await res.json()
      return { products: data.products || [], total: data.total ?? (data.products || []).length }
    } catch {
      // Offline fallback: the same local list the mock getAll works from.
      let result = [...products]
      if (params.category) result = result.filter((p) => p.category === params.category)
      if (params.search) {
        const q = params.search.toLowerCase()
        result = result.filter((p) => p.name.toLowerCase().includes(q))
      }
      return { products: result, total: result.length }
    }
  },

  getAll: async (params = {}) => {
    await delay()
    let result = [...products]

    if (params.category) result = result.filter((p) => p.category === params.category)
    if (params.featured === true || params.featured === 'true') result = result.filter((p) => p.isFeatured)
    if (params.newArrival === true || params.newArrival === 'true') result = result.filter((p) => p.isNewArrival)
    if (params.search) {
      const q = params.search.toLowerCase()
      result = result.filter((p) =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.tags?.some((t) => t.toLowerCase().includes(q))
      )
    }
    if (params.minPrice) result = result.filter((p) => p.price >= parseFloat(params.minPrice))
    if (params.maxPrice) result = result.filter((p) => p.price <= parseFloat(params.maxPrice))
    if (params.rating) result = result.filter((p) => p.rating >= parseFloat(params.rating))

    switch (params.sort) {
      case 'price_asc': result.sort((a, b) => a.price - b.price); break
      case 'price_desc': result.sort((a, b) => b.price - a.price); break
      case 'rating': result.sort((a, b) => b.rating - a.rating); break
      default: result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    }

    const page = parseInt(params.page) || 1
    const limit = parseInt(params.limit) || 12
    const total = result.length
    const paginated = result.slice((page - 1) * limit, page * limit)

    return { products: paginated, page, pages: Math.ceil(total / limit), total }
  },

  // Real: GET /api/products/:id
  getById: async (id) => {
    await delay()
    const p = products.find((p) => p._id === id)
    if (!p) err('Product not found', 404)
    return { ...p }
  },

  // Real: GET /api/products/categories
  getCategories: async () => {
    await delay(150)
    return [...new Set(products.map((p) => p.category))]
  },

  // Real: POST /api/products/:id/reviews
  addReview: async (id, { rating, comment }) => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    const p = products.find((p) => p._id === id)
    if (!p) err('Product not found', 404)
    if (p.reviews?.some((r) => r._id.includes(user._id))) err('Already reviewed')
    const review = {
      _id: `r_${user._id}_${Date.now()}`,
      name: user.name,
      rating,
      comment,
      createdAt: new Date().toISOString(),
    }
    p.reviews = [...(p.reviews || []), review]
    p.numReviews = p.reviews.length
    p.rating = p.reviews.reduce((s, r) => s + r.rating, 0) / p.reviews.length
    return { message: 'Review added' }
  },
}

// ─── User API ─────────────────────────────────────────────────────────────────
export const userApi = {
  // Real: POST /api/users/register
  register: async ({ name, email, password }) => {
    await delay()
    if (users.find((u) => u.email === email)) err('Email already in use')
    const user = { _id: `u${Date.now()}`, name, email, password, isAdmin: false, wishlist: [] }
    users.push(user)
    const { password: _, ...safe } = user
    return { user: safe, token: makeToken(user._id) }
  },

  // Real: POST /api/users/login
  login: async ({ email, password }) => {
    const toAuthShape = (payload) => {
      if (!payload || typeof payload !== 'object') return null

      const token = payload.token || payload.accessToken || payload.jwt
      const payloadUser = payload.user || payload.data?.user
      const user = payloadUser || (payload._id || payload.id ? payload : null)

      if (!user) return null

      const userId = user._id || user.id
      const normalizedToken = token || (userId ? makeToken(userId) : null)
      if (!normalizedToken) return null

      return { user, token: normalizedToken }
    }

    const localLogin = () => {
      const user = users.find((u) => u.email === email && u.password === password)
      if (!user) err('Invalid email or password', 401)
      const { password: _, ...safe } = user
      return { user: safe, token: makeToken(user._id) }
    }

    try {
      const BASE_URL = getApiBaseUrl()
      const res = await fetch(`${BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      })

      const text = await res.text()
      if (!res.ok) {
  if (res.status === 403) {
    window.__ATTACK_BLOCKED__ = true;
    throw new Error("🚨 SQL Injection Attack Blocked");
  }
  throw new Error(text || 'Login failed');
}

      let parsed
      try {
        parsed = JSON.parse(text)
      } catch {
        throw new Error('Login endpoint returned invalid JSON')
      }

      const normalized = toAuthShape(parsed)
      if (!normalized) {
        throw new Error('Login endpoint returned unsupported response shape')
      }

      return normalized
    } catch (e) {
  console.log("LOGIN ERROR:", e); // 👈 DEBUG

  if (
    e?.message?.includes('Blocked') ||
    e?.message?.includes('SQL') ||
    e?.message?.includes('Forbidden')
  ) {
    window.__ATTACK_BLOCKED__ = true;
    throw new Error("🚨 SQL Injection Attack Blocked");
  }

  return localLogin();
}
  },

  // Real: GET /api/users/profile
  getProfile: async () => {
    await delay(150)
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    const { password: _, ...safe } = user
    return safe
  },

  // Real: PUT /api/users/profile
  updateProfile: async (data) => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    if (data.name) user.name = data.name
    if (data.email) user.email = data.email
    if (data.password) user.password = data.password
    const { password: _, ...safe } = user
    return { user: safe, token: makeToken(user._id) }
  },

  // Real: GET /api/users/wishlist
  getWishlist: async () => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    return products.filter((p) => (user.wishlist || []).includes(p._id))
  },

  // Real: POST /api/users/wishlist/:productId
  toggleWishlist: async (productId) => {
    await delay(200)
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    user.wishlist = user.wishlist || []
    const idx = user.wishlist.indexOf(productId)
    if (idx > -1) user.wishlist.splice(idx, 1)
    else user.wishlist.push(productId)
    return { wishlist: user.wishlist }
  },
}

// ─── Order API ────────────────────────────────────────────────────────────────
export const orderApi = {
  // Real: POST /api/orders
  create: async ({ items, shippingAddress, paymentMethod }) => {
    await delay(500)
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)

    const orderItems = []
    let subtotal = 0
    for (const item of items) {
      const product = products.find((p) => p._id === item.product)
      if (!product) err(`Product not found: ${item.product}`, 404)
      if (product.stock < item.quantity) err(`${product.name} is out of stock`)
      orderItems.push({
        product: product._id,
        name: product.name,
        image: product.images?.[0],
        price: product.price,
        quantity: item.quantity,
      })
      subtotal += product.price * item.quantity
      product.stock -= item.quantity
    }

    const shippingPrice = subtotal >= 50 ? 0 : 5.99
    const taxPrice = parseFloat((subtotal * 0.08).toFixed(2))
    const totalPrice = parseFloat((subtotal + shippingPrice + taxPrice).toFixed(2))

    const order = {
      _id: `ord_${(++nextOrderId).toString(36)}${Date.now().toString(36)}`,
      user: { _id: user._id, name: user.name, email: user.email },
      items: orderItems,
      shippingAddress,
      paymentMethod,
      subtotal,
      shippingPrice,
      taxPrice,
      totalPrice,
      status: 'pending',
      isPaid: true,
      paidAt: new Date().toISOString(),
      isDelivered: false,
      createdAt: new Date().toISOString(),
    }
    orders.unshift(order)
    return order
  },

  // Real: GET /api/orders/my
  getMyOrders: async () => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    return orders.filter((o) => o.user._id === user._id)
  },

  // Real: GET /api/orders/:id
  getById: async (id) => {
    await delay()
    const user = getCurrentUser()
    if (!user) err('Not authenticated', 401)
    const order = orders.find((o) => o._id === id)
    if (!order) err('Order not found', 404)
    if (order.user._id !== user._id && !user.isAdmin) err('Not authorized', 403)
    return order
  },
}

// ─── Admin API ────────────────────────────────────────────────────────────────
export const adminApi = {
  // Real: GET /api/admin/stats
  getStats: async () => {
    await delay()
    return {
      totalProducts: products.length,
      totalOrders: orders.length,
      totalUsers: users.length,
      totalRevenue: orders.reduce((s, o) => s + o.totalPrice, 0),
    }
  },

  // Real: POST /api/admin/product
  createProduct: async (data) => {
    await delay()
    const product = {
      ...data,
      _id: `p${Date.now()}`,
      rating: 0,
      numReviews: 0,
      reviews: [],
      createdAt: new Date().toISOString(),
    }
    products.unshift(product)
    return product
  },

  // Real: PUT /api/admin/product/:id
  updateProduct: async (id, data) => {
    await delay()
    const idx = products.findIndex((p) => p._id === id)
    if (idx === -1) err('Product not found', 404)
    products[idx] = { ...products[idx], ...data }
    return products[idx]
  },

  // Real: DELETE /api/admin/product/:id
  deleteProduct: async (id) => {
    await delay()
    const idx = products.findIndex((p) => p._id === id)
    if (idx === -1) err('Product not found', 404)
    products.splice(idx, 1)
    return { message: 'Product deleted' }
  },

  // Real: GET /api/admin/orders
  getOrders: async (params = {}) => {
    await delay()
    const page = parseInt(params.page) || 1
    const limit = 20
    const total = orders.length
    const paginated = orders.slice((page - 1) * limit, page * limit)
    return { orders: paginated, page, pages: Math.ceil(total / limit), total }
  },

  // Real: PUT /api/admin/orders/:id/status
  updateOrderStatus: async (id, status) => {
    await delay()
    const order = orders.find((o) => o._id === id)
    if (!order) err('Order not found', 404)
    order.status = status
    if (status === 'delivered') {
      order.isDelivered = true
      order.deliveredAt = new Date().toISOString()
    }
    return order
  },

  // Real: GET /api/admin/users
  getUsers: async () => {
    await delay()
    return users.map((user) => {
    const {  ...safeUser } = user;
    return safeUser;
  });
  },
}

export default { productApi, userApi, orderApi, adminApi }
