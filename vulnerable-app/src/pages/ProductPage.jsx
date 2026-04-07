import { useState, useEffect } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { productApi } from '../services/api'
import { useCart } from '../context/CartContext'
import { useWishlist } from '../context/WishlistContext'
import { useAuth } from '../context/AuthContext'
import { formatPrice, formatDate, discount } from '../utils'
import toast from 'react-hot-toast'
import './ProductPage.css'

function Stars({ rating, interactive = false, onRate }) {
  const [hover, setHover] = useState(0)
  return (
    <div className={`stars ${interactive ? 'interactive' : ''}`}>
      {[1, 2, 3, 4, 5].map((s) => (
        <span
          key={s}
          className={s <= (interactive ? hover || rating : Math.round(rating)) ? '' : 'empty'}
          onClick={() => interactive && onRate && onRate(s)}
          onMouseEnter={() => interactive && setHover(s)}
          onMouseLeave={() => interactive && setHover(0)}
        >★</span>
      ))}
    </div>
  )
}

export default function ProductPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const { addToCart } = useCart()
  const { toggleWishlist, isWishlisted } = useWishlist()
  const { user } = useAuth()

  const [product, setProduct] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeImage, setActiveImage] = useState(0)
  const [quantity, setQuantity] = useState(1)
  const [addingCart, setAddingCart] = useState(false)

  // Review form
  const [reviewRating, setReviewRating] = useState(5)
  const [reviewComment, setReviewComment] = useState('')
  const [submittingReview, setSubmittingReview] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    productApi.getById(id)
      .then((p) => { setProduct(p); setActiveImage(0) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  const handleAddToCart = async () => {
    setAddingCart(true)
    await new Promise((r) => setTimeout(r, 300))
    addToCart(product, quantity)
    toast.success('Added to cart!')
    setAddingCart(false)
  }

  const handleWishlist = async () => {
    if (!user) { toast.error('Sign in to save to wishlist'); return }
    await toggleWishlist(product._id)
    toast.success(isWishlisted(product._id) ? 'Removed from wishlist' : 'Saved!')
  }

  const handleSubmitReview = async (e) => {
    e.preventDefault()
    if (!user) { toast.error('Sign in to leave a review'); return }
    if (!reviewComment.trim()) { toast.error('Please write a comment'); return }
    setSubmittingReview(true)
    try {
      await productApi.addReview(id, { rating: reviewRating, comment: reviewComment })
      toast.success('Review submitted!')
      setReviewComment('')
      setReviewRating(5)
      const updated = await productApi.getById(id)
      setProduct(updated)
    } catch (err) {
      toast.error(err.message)
    } finally {
      setSubmittingReview(false)
    }
  }

  if (loading) return (
    <div className="container" style={{ padding: '60px 0' }}>
      <div className="product-detail-skeleton">
        <div className="skeleton" style={{ height: '420px', borderRadius: '10px' }} />
        <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          {[80, 60, 40, 40, 100, 60].map((w, i) => (
            <div key={i} className="skeleton" style={{ height: '18px', width: `${w}%` }} />
          ))}
        </div>
      </div>
    </div>
  )

  if (error) return (
    <div className="container" style={{ padding: '60px 0', textAlign: 'center' }}>
      <p style={{ color: 'var(--error)', marginBottom: '16px' }}>⚠ {error}</p>
      <button className="btn btn-secondary" onClick={() => navigate(-1)}>← Go Back</button>
    </div>
  )

  if (!product) return null

  const disc = discount(product.originalPrice, product.price)
  const wishlisted = isWishlisted(product._id)

  return (
    <div className="product-page container">
      {/* Breadcrumb */}
      <nav className="breadcrumb">
        <Link to="/">Home</Link>
        <span>/</span>
        <Link to="/shop">Shop</Link>
        <span>/</span>
        <Link to={`/shop?category=${encodeURIComponent(product.category)}`}>{product.category}</Link>
        <span>/</span>
        <span>{product.name}</span>
      </nav>

      <div className="product-detail">
        {/* Images */}
        <div className="product-images">
          <div className="main-image">
            <img
              src={product.images?.[activeImage] || 'https://via.placeholder.com/600x500?text=No+Image'}
              alt={product.name}
              onError={(e) => { e.target.src = 'https://via.placeholder.com/600x500?text=No+Image' }}
            />
            {disc > 0 && <span className="badge badge-sale img-badge">−{disc}% off</span>}
          </div>
          {product.images?.length > 1 && (
            <div className="thumb-row">
              {product.images.map((img, i) => (
                <button
                  key={i}
                  className={`thumb ${i === activeImage ? 'active' : ''}`}
                  onClick={() => setActiveImage(i)}
                >
                  <img src={img} alt={`View ${i + 1}`} />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Info */}
        <div className="product-info">
          <p className="product-brand">{product.brand}</p>
          <h1 className="product-name">{product.name}</h1>

          {product.numReviews > 0 && (
            <div className="product-rating-row">
              <Stars rating={product.rating} />
              <span className="rating-value">{product.rating.toFixed(1)}</span>
              <a href="#reviews" className="rating-count">({product.numReviews} reviews)</a>
            </div>
          )}

          <div className="product-price-row">
            <span className="product-price">{formatPrice(product.price)}</span>
            {product.originalPrice && (
              <span className="product-price-original">{formatPrice(product.originalPrice)}</span>
            )}
            {disc > 0 && <span className="badge badge-sale">Save {disc}%</span>}
          </div>

          <p className="product-desc">{product.description}</p>

          <div className="stock-info">
            {product.stock > 0 ? (
              <span className="in-stock">
                ✓ In stock
                {product.stock <= 5 && <span className="low-stock"> — only {product.stock} left</span>}
              </span>
            ) : (
              <span className="out-stock">✗ Out of stock</span>
            )}
          </div>

          {product.stock > 0 && (
            <div className="qty-row">
              <label>Qty:</label>
              <div className="qty-control">
                <button onClick={() => setQuantity((q) => Math.max(1, q - 1))}>−</button>
                <span>{quantity}</span>
                <button onClick={() => setQuantity((q) => Math.min(product.stock, q + 1))}>+</button>
              </div>
            </div>
          )}

          <div className="product-actions">
            <button
              className="btn btn-primary btn-lg"
              onClick={handleAddToCart}
              disabled={product.stock === 0 || addingCart}
            >
              {addingCart ? <><span className="spinner" /> Adding…</> : product.stock === 0 ? 'Out of Stock' : 'Add to Cart'}
            </button>
            <button
              className={`btn btn-secondary btn-lg wishlist-toggle ${wishlisted ? 'wishlisted' : ''}`}
              onClick={handleWishlist}
            >
              {wishlisted ? '♥ Saved' : '♡ Wishlist'}
            </button>
          </div>

          <div className="product-meta">
            <div><span>Category</span><Link to={`/shop?category=${encodeURIComponent(product.category)}`}>{product.category}</Link></div>
            {product.brand && <div><span>Brand</span>{product.brand}</div>}
            {product.tags?.length > 0 && (
              <div><span>Tags</span>
                <div className="tag-list">{product.tags.map((t) => <span key={t} className="tag">{t}</span>)}</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Reviews */}
      <section className="reviews-section" id="reviews">
        <h2>Customer Reviews</h2>

        {product.reviews?.length === 0 && (
          <p className="no-reviews">No reviews yet — be the first!</p>
        )}

        <div className="reviews-list">
          {product.reviews?.map((r) => (
            <div key={r._id} className="review-card">
              <div className="review-header">
                <div className="reviewer-avatar">{r.name?.[0]?.toUpperCase()}</div>
                <div>
                  <strong>{r.name}</strong>
                  <div className="review-meta">
                    <Stars rating={r.rating} />
                    <span>{formatDate(r.createdAt)}</span>
                  </div>
                </div>
              </div>
              <p className="review-comment">{r.comment}</p>
            </div>
          ))}
        </div>

        {/* Review form */}
        <div className="review-form-wrap">
          <h3>Write a Review</h3>
          {!user ? (
            <p className="text-muted text-sm">
              <Link to="/login" style={{ color: 'var(--brand)' }}>Sign in</Link> to leave a review.
            </p>
          ) : (
            <form onSubmit={handleSubmitReview} className="review-form">
              <div className="form-group">
                <label className="form-label">Your Rating</label>
                <Stars rating={reviewRating} interactive onRate={setReviewRating} />
              </div>
              <div className="form-group">
                <label className="form-label">Your Review</label>
                <textarea
                  className="form-input"
                  rows={4}
                  placeholder="What did you think of this product?"
                  value={reviewComment}
                  onChange={(e) => setReviewComment(e.target.value)}
                  required
                />
              </div>
              <button type="submit" className="btn btn-primary" disabled={submittingReview}>
                {submittingReview ? <><span className="spinner" /> Submitting…</> : 'Submit Review'}
              </button>
            </form>
          )}
        </div>
      </section>
    </div>
  )
}
