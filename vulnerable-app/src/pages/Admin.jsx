import { useState, useEffect } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { adminApi } from '../services/api'
import { formatPrice, formatDate } from '../utils'
import toast from 'react-hot-toast'
import './Admin.css'

const EMPTY_PRODUCT = {
  name: '', slug: '', description: '', price: '', originalPrice: '',
  category: 'Electronics', brand: '', stock: '', isFeatured: false,
  isNewArrival: false, images: '', tags: '',
}

const CATEGORIES = ['Electronics', 'Clothing', 'Home & Garden', 'Sports', 'Books', 'Toys', 'Beauty', 'Food']

export default function Admin() {
  const { user } = useAuth()
  const [tab, setTab] = useState('dashboard')

  if (!user?.isAdmin) return <Navigate to="/" replace />

  return (
    <div className="admin-page container">
      <div className="admin-header">
        <h1>Admin Panel</h1>
        <p className="text-muted text-sm">Manage products, orders, and users</p>
      </div>

      <div className="admin-tabs">
        {['dashboard', 'products', 'orders', 'users'].map((t) => (
          <button key={t} className={`tab-btn ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      <div className="admin-content">
        {tab === 'dashboard' && <Dashboard />}
        {tab === 'products' && <Products />}
        {tab === 'orders' && <AdminOrders />}
        {tab === 'users' && <Users />}
      </div>
    </div>
  )
}

function Dashboard() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    adminApi.getStats().then(setStats).finally(() => setLoading(false))
  }, [])

  if (loading) return <div style={{ textAlign: 'center', padding: '40px' }}><span className="spinner spinner-lg" /></div>

  return (
    <div className="dashboard">
      <div className="stat-cards">
        {[
          { label: 'Total Revenue', value: formatPrice(stats?.totalRevenue || 0), icon: '💰' },
          { label: 'Total Orders', value: stats?.totalOrders || 0, icon: '📦' },
          { label: 'Products', value: stats?.totalProducts || 0, icon: '🏷' },
          { label: 'Users', value: stats?.totalUsers || 0, icon: '👥' },
        ].map((s) => (
          <div key={s.label} className="stat-card">
            <span className="stat-icon">{s.icon}</span>
            <div>
              <div className="stat-value">{s.value}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function Products() {
  const [products, setProducts] = useState([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editProduct, setEditProduct] = useState(null)
  const [form, setForm] = useState(EMPTY_PRODUCT)
  const [saving, setSaving] = useState(false)

  const load = () => {
    setLoading(true)
    import('../services/api').then(({ productApi }) =>
      productApi.getAll({ limit: 100 }).then((d) => setProducts(d.products)).finally(() => setLoading(false))
    )
  }

  useEffect(() => { load() }, [])

  const openCreate = () => { setForm(EMPTY_PRODUCT); setEditProduct(null); setShowForm(true) }
  const openEdit = (p) => {
    setForm({
      ...p,
      images: p.images?.join(', ') || '',
      tags: p.tags?.join(', ') || '',
      originalPrice: p.originalPrice || '',
    })
    setEditProduct(p)
    setShowForm(true)
  }

  const handleSave = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      const payload = {
        ...form,
        price: parseFloat(form.price),
        originalPrice: form.originalPrice ? parseFloat(form.originalPrice) : undefined,
        stock: parseInt(form.stock),
        images: form.images.split(',').map((s) => s.trim()).filter(Boolean),
        tags: form.tags.split(',').map((s) => s.trim()).filter(Boolean),
        slug: form.slug || form.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, ''),
      }
      if (editProduct) {
        await adminApi.updateProduct(editProduct._id, payload)
        toast.success('Product updated!')
      } else {
        await adminApi.createProduct(payload)
        toast.success('Product created!')
      }
      setShowForm(false)
      load()
    } catch (err) {
      toast.error(err.message)
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async (id, name) => {
    if (!confirm(`Delete "${name}"?`)) return
    try {
      await adminApi.deleteProduct(id)
      toast.success('Product deleted')
      load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  const setF = (k, v) => setForm((f) => ({ ...f, [k]: v }))

  return (
    <div>
      <div className="section-toolbar">
        <h2>Products ({products.length})</h2>
        <button className="btn btn-primary btn-sm" onClick={openCreate}>+ Add Product</button>
      </div>

      {showForm && (
        <div className="admin-form-wrap">
          <h3>{editProduct ? 'Edit Product' : 'New Product'}</h3>
          <form onSubmit={handleSave} className="admin-product-form">
            <div className="fg2">
              <div className="form-group">
                <label className="form-label">Name *</label>
                <input className="form-input" value={form.name} onChange={(e) => setF('name', e.target.value)} required />
              </div>
              <div className="form-group">
                <label className="form-label">Slug</label>
                <input className="form-input" value={form.slug} onChange={(e) => setF('slug', e.target.value)} placeholder="auto-generated if empty" />
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Description *</label>
              <textarea className="form-input" rows={3} value={form.description} onChange={(e) => setF('description', e.target.value)} required />
            </div>
            <div className="fg3">
              <div className="form-group">
                <label className="form-label">Price *</label>
                <input type="number" step="0.01" className="form-input" value={form.price} onChange={(e) => setF('price', e.target.value)} required />
              </div>
              <div className="form-group">
                <label className="form-label">Original Price</label>
                <input type="number" step="0.01" className="form-input" value={form.originalPrice} onChange={(e) => setF('originalPrice', e.target.value)} />
              </div>
              <div className="form-group">
                <label className="form-label">Stock *</label>
                <input type="number" className="form-input" value={form.stock} onChange={(e) => setF('stock', e.target.value)} required />
              </div>
            </div>
            <div className="fg2">
              <div className="form-group">
                <label className="form-label">Category *</label>
                <select className="form-select" value={form.category} onChange={(e) => setF('category', e.target.value)}>
                  {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Brand</label>
                <input className="form-input" value={form.brand} onChange={(e) => setF('brand', e.target.value)} />
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Images (comma-separated URLs)</label>
              <input className="form-input" value={form.images} onChange={(e) => setF('images', e.target.value)} placeholder="https://..." />
            </div>
            <div className="form-group">
              <label className="form-label">Tags (comma-separated)</label>
              <input className="form-input" value={form.tags} onChange={(e) => setF('tags', e.target.value)} placeholder="tag1, tag2" />
            </div>
            <div className="fg2">
              <label className="check-label">
                <input type="checkbox" checked={form.isFeatured} onChange={(e) => setF('isFeatured', e.target.checked)} />
                Featured product
              </label>
              <label className="check-label">
                <input type="checkbox" checked={form.isNewArrival} onChange={(e) => setF('isNewArrival', e.target.checked)} />
                New arrival
              </label>
            </div>
            <div className="form-actions">
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? <><span className="spinner" /> Saving…</> : editProduct ? 'Update Product' : 'Create Product'}
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => setShowForm(false)}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px' }}><span className="spinner spinner-lg" /></div>
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr><th>Product</th><th>Category</th><th>Price</th><th>Stock</th><th>Rating</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {products.map((p) => (
                <tr key={p._id}>
                  <td>
                    <div className="admin-product-cell">
                      <img src={p.images?.[0]} alt={p.name} onError={(e) => { e.target.style.display = 'none' }} />
                      <span>{p.name}</span>
                    </div>
                  </td>
                  <td>{p.category}</td>
                  <td>{formatPrice(p.price)}</td>
                  <td>
                    <span className={p.stock === 0 ? 'badge badge-out' : p.stock <= 5 ? 'badge badge-sale' : ''}>
                      {p.stock}
                    </span>
                  </td>
                  <td>{p.rating?.toFixed(1)} ★ ({p.numReviews})</td>
                  <td>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button className="btn btn-secondary btn-sm" onClick={() => openEdit(p)}>Edit</button>
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete(p._id, p.name)}>Del</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function AdminOrders() {
  const [orders, setOrders] = useState([])
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    adminApi.getOrders().then((d) => setOrders(d.orders)).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleStatus = async (id, status) => {
    try {
      await adminApi.updateOrderStatus(id, status)
      toast.success('Status updated')
      load()
    } catch (err) {
      toast.error(err.message)
    }
  }

  return (
    <div>
      <div className="section-toolbar"><h2>Orders ({orders.length})</h2></div>
      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px' }}><span className="spinner spinner-lg" /></div>
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr><th>Order ID</th><th>Customer</th><th>Date</th><th>Total</th><th>Status</th><th>Update</th></tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <tr key={o._id}>
                  <td><code style={{ fontSize: '0.78rem' }}>#{o._id.slice(-8).toUpperCase()}</code></td>
                  <td>{o.user?.name || 'N/A'}<br /><small style={{ color: 'var(--text-muted)' }}>{o.user?.email}</small></td>
                  <td>{formatDate(o.createdAt)}</td>
                  <td><strong>{formatPrice(o.totalPrice)}</strong></td>
                  <td><span className="badge" style={{ background: '#f3f4f6', color: '#374151' }}>{o.status}</span></td>
                  <td>
                    <select
                      className="form-select"
                      value={o.status}
                      onChange={(e) => handleStatus(o._id, e.target.value)}
                      style={{ fontSize: '0.8rem', padding: '5px 8px' }}
                    >
                      {['pending', 'processing', 'shipped', 'delivered', 'cancelled'].map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function Users() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    adminApi.getUsers().then(setUsers).finally(() => setLoading(false))
  }, [])

  return (
    <div>
      <div className="section-toolbar"><h2>Users ({users.length})</h2></div>
      {loading ? (
        <div style={{ textAlign: 'center', padding: '40px' }}><span className="spinner spinner-lg" /></div>
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr><th>Name</th><th>Email</th><th>Role</th><th>Joined</th><th>Wishlist</th></tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u._id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'var(--brand-light)', color: 'var(--brand)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem', flexShrink: 0 }}>
                        {u.name?.[0]?.toUpperCase()}
                      </div>
                      {u.name}
                    </div>
                  </td>
                  <td>{u.email}</td>
                  <td>{u.isAdmin ? <span className="badge badge-sale">Admin</span> : <span className="badge" style={{ background: '#f3f4f6', color: '#374151' }}>User</span>}</td>
                  <td>{formatDate(u.createdAt)}</td>
                  <td>{u.wishlist?.length || 0} items</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
