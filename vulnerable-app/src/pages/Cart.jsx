import { Link, useNavigate } from 'react-router-dom'
import { useCart } from '../context/CartContext'
import { formatPrice } from '../utils'
import toast from 'react-hot-toast'
import './Cart.css'

export default function Cart() {
  const { items, removeFromCart, updateQuantity, subtotal, totalItems } = useCart()
  const navigate = useNavigate()

  const shipping = subtotal >= 50 ? 0 : 5.99
  const tax = +(subtotal * 0.08).toFixed(2)
  const total = +(subtotal + shipping + tax).toFixed(2)

  const handleRemove = (item) => {
    removeFromCart(item._id)
    toast.success(`Removed "${item.name.slice(0, 24)}…"`, { duration: 1800 })
  }

  if (items.length === 0) return (
    <div className="container">
      <div className="empty-state" style={{ padding: '80px 0' }}>
        <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.2">
          <path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z" />
          <line x1="3" y1="6" x2="21" y2="6" />
          <path d="M16 10a4 4 0 0 1-8 0" />
        </svg>
        <h3>Your cart is empty</h3>
        <p style={{ marginBottom: '20px' }}>Looks like you haven't added anything yet.</p>
        <Link to="/shop" className="btn btn-primary">Browse Products</Link>
      </div>
    </div>
  )

  return (
    <div className="cart-page container">
      <div className="page-header">
        <h1>Your Cart <span className="cart-count">{totalItems} item{totalItems !== 1 ? 's' : ''}</span></h1>
      </div>

      <div className="cart-layout">
        {/* Items */}
        <div className="cart-items">
          {items.map((item) => (
            <div key={item._id} className="cart-item">
              <Link to={`/product/${item._id}`} className="cart-item-img">
                <img
                  src={item.images?.[0] || 'https://via.placeholder.com/100?text=?'}
                  alt={item.name}
                  onError={(e) => { e.target.src = 'https://via.placeholder.com/100?text=?' }}
                />
              </Link>
              <div className="cart-item-info">
                <Link to={`/product/${item._id}`} className="cart-item-name">{item.name}</Link>
                <p className="cart-item-cat">{item.category}</p>
                {item.stock <= 5 && item.stock > 0 && (
                  <p className="cart-item-warn">Only {item.stock} left in stock</p>
                )}
              </div>
              <div className="cart-item-qty">
                <button onClick={() => updateQuantity(item._id, item.quantity - 1)}>−</button>
                <span>{item.quantity}</span>
                <button onClick={() => updateQuantity(item._id, Math.min(item.stock, item.quantity + 1))}>+</button>
              </div>
              <div className="cart-item-price">
                <span className="item-total">{formatPrice(item.price * item.quantity)}</span>
                <span className="item-unit">{formatPrice(item.price)} each</span>
              </div>
              <button className="cart-item-remove" onClick={() => handleRemove(item)} aria-label="Remove">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M3 6h18M19 6l-1 14H6L5 6M10 11v6M14 11v6M9 6V4h6v2" />
                </svg>
              </button>
            </div>
          ))}

          <div className="cart-continue">
            <Link to="/shop" className="btn btn-ghost btn-sm">← Continue Shopping</Link>
          </div>
        </div>

        {/* Summary */}
        <div className="cart-summary">
          <h2>Order Summary</h2>
          <div className="summary-rows">
            <div className="summary-row">
              <span>Subtotal</span>
              <span>{formatPrice(subtotal)}</span>
            </div>
            <div className="summary-row">
              <span>Shipping</span>
              <span>{shipping === 0 ? <span className="free-ship">Free</span> : formatPrice(shipping)}</span>
            </div>
            {shipping > 0 && (
              <p className="ship-note">Add {formatPrice(50 - subtotal)} more for free shipping</p>
            )}
            <div className="summary-row">
              <span>Tax (8%)</span>
              <span>{formatPrice(tax)}</span>
            </div>
            <div className="divider" />
            <div className="summary-row summary-total">
              <span>Total</span>
              <span>{formatPrice(total)}</span>
            </div>
          </div>
          <button
            className="btn btn-primary btn-full btn-lg"
            onClick={() => navigate('/checkout')}
          >
            Proceed to Checkout
          </button>
          <div className="payment-icons">
            <span>💳</span><span>🔒</span>
            <small>Secure checkout</small>
          </div>
        </div>
      </div>
    </div>
  )
}
