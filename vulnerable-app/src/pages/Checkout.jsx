import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useCart } from '../context/CartContext'
import { useAuth } from '../context/AuthContext'
import { orderApi } from '../services/api'
import { formatPrice } from '../utils'
import toast from 'react-hot-toast'
import './Checkout.css'

const INITIAL_ADDR = { fullName: '', street: '', city: '', state: '', zip: '', country: 'US' }

export default function Checkout() {
  const { items, subtotal, clearCart } = useCart()
  const { user } = useAuth()
  const navigate = useNavigate()

  const [address, setAddress] = useState({
    ...INITIAL_ADDR,
    fullName: user?.name || '',
  })
  const [paymentMethod, setPaymentMethod] = useState('card')
  const [cardInfo, setCardInfo] = useState({ number: '', expiry: '', cvv: '' })
  const [placing, setPlacing] = useState(false)
  const [errors, setErrors] = useState({})

  const shipping = subtotal >= 50 ? 0 : 5.99
  const tax = +(subtotal * 0.08).toFixed(2)
  const total = +(subtotal + shipping + tax).toFixed(2)

  const validate = () => {
    const e = {}
    if (!address.fullName.trim()) e.fullName = 'Required'
    if (!address.street.trim()) e.street = 'Required'
    if (!address.city.trim()) e.city = 'Required'
    if (!address.state.trim()) e.state = 'Required'
    if (!address.zip.trim()) e.zip = 'Required'
    if (paymentMethod === 'card') {
      if (cardInfo.number.replace(/\s/g, '').length < 16) e.cardNumber = 'Enter 16-digit card number'
      if (!cardInfo.expiry.match(/^\d{2}\/\d{2}$/)) e.expiry = 'MM/YY format'
      if (cardInfo.cvv.length < 3) e.cvv = 'Enter CVV'
    }
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const handlePlace = async () => {
    if (!validate()) return
    setPlacing(true)
    try {
      const orderItems = items.map((i) => ({
        product: i._id,
        name: i.name,
        price: i.price,
        image: i.images?.[0] || i.image,
        quantity: i.quantity,
      }))
      const order = await orderApi.create({ items: orderItems, shippingAddress: address, paymentMethod })
      clearCart()
      toast.success('Order placed successfully!')
      navigate(`/orders/${order._id}`)
    } catch (err) {
      toast.error(err.message)
    } finally {
      setPlacing(false)
    }
  }

  const setAddr = (field, val) => setAddress((a) => ({ ...a, [field]: val }))
  const setCard = (field, val) => setCardInfo((c) => ({ ...c, [field]: val }))

  const formatCard = (val) => val.replace(/\D/g, '').slice(0, 16).replace(/(.{4})/g, '$1 ').trim()
  const formatExpiry = (val) => {
    const digits = val.replace(/\D/g, '').slice(0, 4)
    return digits.length > 2 ? digits.slice(0, 2) + '/' + digits.slice(2) : digits
  }

  if (items.length === 0) {
    navigate('/cart')
    return null
  }

  return (
    <div className="checkout-page container">
      <div className="page-header"><h1>Checkout</h1></div>

      <div className="checkout-layout">
        <div className="checkout-forms">
          {/* Shipping */}
          <div className="checkout-section">
            <h2><span className="step-num">1</span> Shipping Address</h2>
            <div className="form-row-2">
              <div className="form-group">
                <label className="form-label">Full Name *</label>
                <input className={`form-input ${errors.fullName ? 'error' : ''}`} value={address.fullName} onChange={(e) => setAddr('fullName', e.target.value)} />
                {errors.fullName && <span className="form-error">{errors.fullName}</span>}
              </div>
              <div className="form-group">
                <label className="form-label">Country</label>
                <select className="form-select" value={address.country} onChange={(e) => setAddr('country', e.target.value)}>
                  <option value="US">United States</option>
                  <option value="CA">Canada</option>
                  <option value="GB">United Kingdom</option>
                  <option value="AU">Australia</option>
                  <option value="IN">India</option>
                </select>
              </div>
            </div>
            <div className="form-group">
              <label className="form-label">Street Address *</label>
              <input className={`form-input ${errors.street ? 'error' : ''}`} placeholder="123 Main St, Apt 4" value={address.street} onChange={(e) => setAddr('street', e.target.value)} />
              {errors.street && <span className="form-error">{errors.street}</span>}
            </div>
            <div className="form-row-3">
              <div className="form-group">
                <label className="form-label">City *</label>
                <input className={`form-input ${errors.city ? 'error' : ''}`} value={address.city} onChange={(e) => setAddr('city', e.target.value)} />
                {errors.city && <span className="form-error">{errors.city}</span>}
              </div>
              <div className="form-group">
                <label className="form-label">State *</label>
                <input className={`form-input ${errors.state ? 'error' : ''}`} placeholder="NY" value={address.state} onChange={(e) => setAddr('state', e.target.value)} />
                {errors.state && <span className="form-error">{errors.state}</span>}
              </div>
              <div className="form-group">
                <label className="form-label">ZIP / Postal *</label>
                <input className={`form-input ${errors.zip ? 'error' : ''}`} value={address.zip} onChange={(e) => setAddr('zip', e.target.value)} />
                {errors.zip && <span className="form-error">{errors.zip}</span>}
              </div>
            </div>
          </div>

          {/* Payment */}
          <div className="checkout-section">
            <h2><span className="step-num">2</span> Payment Method</h2>
            <div className="payment-methods">
              {[
                { value: 'card', label: '💳 Credit / Debit Card' },
                { value: 'paypal', label: '🅿 PayPal' },
                { value: 'cod', label: '💵 Cash on Delivery' },
              ].map((m) => (
                <label key={m.value} className={`payment-option ${paymentMethod === m.value ? 'selected' : ''}`}>
                  <input type="radio" name="payment" value={m.value} checked={paymentMethod === m.value} onChange={() => setPaymentMethod(m.value)} />
                  {m.label}
                </label>
              ))}
            </div>

            {paymentMethod === 'card' && (
              <div className="card-form">
                <div className="form-group">
                  <label className="form-label">Card Number</label>
                  <input
                    className={`form-input card-input ${errors.cardNumber ? 'error' : ''}`}
                    placeholder="1234 5678 9012 3456"
                    value={cardInfo.number}
                    onChange={(e) => setCard('number', formatCard(e.target.value))}
                    maxLength={19}
                  />
                  {errors.cardNumber && <span className="form-error">{errors.cardNumber}</span>}
                </div>
                <div className="form-row-2">
                  <div className="form-group">
                    <label className="form-label">Expiry Date</label>
                    <input
                      className={`form-input ${errors.expiry ? 'error' : ''}`}
                      placeholder="MM/YY"
                      value={cardInfo.expiry}
                      onChange={(e) => setCard('expiry', formatExpiry(e.target.value))}
                      maxLength={5}
                    />
                    {errors.expiry && <span className="form-error">{errors.expiry}</span>}
                  </div>
                  <div className="form-group">
                    <label className="form-label">CVV</label>
                    <input
                      className={`form-input ${errors.cvv ? 'error' : ''}`}
                      placeholder="123"
                      value={cardInfo.cvv}
                      onChange={(e) => setCard('cvv', e.target.value.replace(/\D/g, '').slice(0, 4))}
                      maxLength={4}
                    />
                    {errors.cvv && <span className="form-error">{errors.cvv}</span>}
                  </div>
                </div>
                <p className="mock-notice">🔒 This is a mock checkout. No real payment is processed.</p>
              </div>
            )}
            {paymentMethod === 'paypal' && (
              <div className="paypal-note">You'll be redirected to PayPal after placing order. <em>(Mock)</em></div>
            )}
          </div>
        </div>

        {/* Order summary */}
        <div className="checkout-summary">
          <h2>Order Summary</h2>
          <div className="checkout-items">
            {items.map((item) => (
              <div key={item._id} className="checkout-item">
                <div className="ci-img">
                  <img src={item.images?.[0]} alt={item.name} onError={(e) => { e.target.src = 'https://via.placeholder.com/60?text=?' }} />
                  <span className="ci-qty">{item.quantity}</span>
                </div>
                <span className="ci-name">{item.name}</span>
                <span className="ci-price">{formatPrice(item.price * item.quantity)}</span>
              </div>
            ))}
          </div>
          <div className="divider" />
          <div className="summary-rows">
            <div className="summary-row"><span>Subtotal</span><span>{formatPrice(subtotal)}</span></div>
            <div className="summary-row"><span>Shipping</span><span>{shipping === 0 ? 'Free' : formatPrice(shipping)}</span></div>
            <div className="summary-row"><span>Tax</span><span>{formatPrice(tax)}</span></div>
            <div className="divider" />
            <div className="summary-row" style={{ fontWeight: 600, fontSize: '1.05rem' }}><span>Total</span><span>{formatPrice(total)}</span></div>
          </div>
          <button
            className="btn btn-primary btn-full btn-lg"
            onClick={handlePlace}
            disabled={placing}
            style={{ marginTop: '20px' }}
          >
            {placing ? <><span className="spinner" /> Placing Order…</> : `Place Order · ${formatPrice(total)}`}
          </button>
        </div>
      </div>
    </div>
  )
}
