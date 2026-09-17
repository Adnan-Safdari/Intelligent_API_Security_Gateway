import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { orderApi } from '../services/api'
import { formatPrice, formatDate } from '../utils'
import './Orders.css'

const STATUS_COLOR = {
  pending: '#f59e0b',
  processing: '#3b82f6',
  shipped: '#8b5cf6',
  delivered: '#10b981',
  cancelled: '#ef4444',
}

export default function Orders() {
  const [orders, setOrders] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    orderApi.getMyOrders()
      .then(setOrders)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="container" style={{ padding: '40px 0' }}>
      {[1, 2, 3].map((i) => (
        <div key={i} className="skeleton" style={{ height: '100px', marginBottom: '12px', borderRadius: '10px' }} />
      ))}
    </div>
  )

  return (
    <div className="orders-page container">
      <div className="page-header"><h1>My Orders</h1></div>

      {error && <div className="error-box">⚠ {error}</div>}

      {!loading && orders.length === 0 && (
        <div className="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
          </svg>
          <h3>No orders yet</h3>
          <p style={{ marginBottom: '16px' }}>Once you place an order it'll appear here.</p>
          <Link to="/shop" className="btn btn-primary">Start Shopping</Link>
        </div>
      )}

      <div className="orders-list">
        {orders.map((order) => (
          <Link key={order._id} to={`/orders/${order._id}`} className="order-card">
            <div className="order-top">
              <div>
                <span className="order-id">#{order.orderNumber || order._id}</span>
                <span className="order-date">{formatDate(order.createdAt)}</span>
              </div>
              <div
                className="order-status"
                style={{ color: STATUS_COLOR[order.status] || '#666' }}
              >
                {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
              </div>
            </div>
            <div className="order-items-preview">
              {order.items.slice(0, 3).map((item, i) => (
                <div key={i} className="preview-item">
                  <img
                    src={item.image || 'https://via.placeholder.com/40?text=?'}
                    alt={item.name}
                    onError={(e) => { e.target.src = 'https://via.placeholder.com/40?text=?' }}
                  />
                </div>
              ))}
              {order.items.length > 3 && (
                <div className="preview-more">+{order.items.length - 3}</div>
              )}
              <div className="order-summary-text">
                {order.items.length} item{order.items.length !== 1 ? 's' : ''}
              </div>
            </div>
            <div className="order-total-row">
              <span>Total: <strong>{formatPrice(order.totalPrice)}</strong></span>
              <span className="view-detail">View details →</span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}

export function OrderDetail() {
  const { id } = useParams()
  const [order, setOrder] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    orderApi.getById(id)
      .then(setOrder)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="container" style={{ padding: '60px 0', textAlign: 'center' }}><span className="spinner spinner-lg" /></div>
  if (error) return <div className="container" style={{ padding: '40px 0' }}><div className="error-box">⚠ {error}</div></div>
  if (!order) return null

  return (
    <div className="order-detail-page container">
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <h1>Order #{order.orderNumber || order._id}</h1>
          <span className="order-status" style={{ color: STATUS_COLOR[order.status], fontWeight: 600 }}>
            {order.status.charAt(0).toUpperCase() + order.status.slice(1)}
          </span>
        </div>
        <p className="text-muted text-sm" style={{ marginTop: '4px' }}>Placed {formatDate(order.createdAt)}</p>
      </div>

      <div className="order-detail-layout">
        <div>
          <div className="card" style={{ marginBottom: '20px' }}>
            <h3 style={{ marginBottom: '16px', fontWeight: 600, fontSize: '0.9rem' }}>Items Ordered</h3>
            {order.items.map((item, i) => (
              <div key={i} className="od-item">
                <img src={item.image || 'https://via.placeholder.com/60?text=?'} alt={item.name} onError={(e) => { e.target.src = 'https://via.placeholder.com/60?text=?' }} />
                <div className="od-item-info">
                  <strong>{item.name}</strong>
                  <span>Qty: {item.quantity} × {formatPrice(item.price)}</span>
                </div>
                <span className="od-item-total">{formatPrice(item.price * item.quantity)}</span>
              </div>
            ))}
          </div>

          <div className="card">
            <h3 style={{ marginBottom: '12px', fontWeight: 600, fontSize: '0.9rem' }}>Shipping Address</h3>
            <p style={{ lineHeight: 1.8, fontSize: '0.875rem', color: 'var(--text-muted)' }}>
              {order.customerName}<br />
              {order.shippingAddress}
            </p>
          </div>
        </div>

        <div className="card" style={{ alignSelf: 'start' }}>
          <h3 style={{ marginBottom: '16px', fontWeight: 600, fontSize: '0.9rem' }}>Order Summary</h3>
          <div className="summary-rows">
            <div className="summary-row"><span>Subtotal</span><span>{formatPrice(order.subtotal)}</span></div>
            <div className="divider" />
            <div className="summary-row" style={{ fontWeight: 600 }}><span>Total</span><span>{formatPrice(order.totalPrice)}</span></div>
          </div>
        </div>
      </div>
    </div>
  )
}
