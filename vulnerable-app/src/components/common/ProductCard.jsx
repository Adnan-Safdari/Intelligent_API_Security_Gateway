import { Link } from 'react-router-dom'
import { useCart } from '../../context/CartContext'
import { useWishlist } from '../../context/WishlistContext'
import { useAuth } from '../../context/AuthContext'
import { formatPrice, discount } from '../../utils'
import toast from 'react-hot-toast'
import './ProductCard.css'

function Stars({ rating }) {
  return (
    <div className="stars">
      {[1, 2, 3, 4, 5].map((s) => (
        <span key={s} className={s <= Math.round(rating) ? '' : 'empty'}>★</span>
      ))}
    </div>
  )
}

export default function ProductCard({ product }) {
  const { addToCart } = useCart()
  const { toggleWishlist, isWishlisted } = useWishlist()
  const { user } = useAuth()

  const wishlisted = isWishlisted(product._id)
  const disc = discount(product.originalPrice, product.price)

  const handleAdd = (e) => {
    e.preventDefault()
    if (product.stock === 0) return
    addToCart(product, 1)
    toast.success(`${product.name.slice(0, 28)}… added to cart`, { duration: 2000 })
  }

  const handleWishlist = async (e) => {
    e.preventDefault()
    if (!user) { toast.error('Sign in to save to wishlist'); return }
    await toggleWishlist(product._id)
    toast.success(wishlisted ? 'Removed from wishlist' : 'Saved to wishlist', { duration: 1800 })
  }

  return (
    <div className="product-card">
      <Link to={`/product/${product._id}`} className="card-image-wrap">
        <img
          src={product.images?.[0] || 'https://via.placeholder.com/400x300?text=No+Image'}
          alt={product.name}
          loading="lazy"
          onError={(e) => { e.target.src = 'https://via.placeholder.com/400x300?text=No+Image' }}
        />
        <div className="card-badges">
          {product.stock === 0 && <span className="badge badge-out">Out of stock</span>}
          {product.isNewArrival && product.stock > 0 && <span className="badge badge-new">New</span>}
          {disc > 0 && product.stock > 0 && <span className="badge badge-sale">−{disc}%</span>}
        </div>
        <button
          className={`wishlist-btn ${wishlisted ? 'active' : ''}`}
          onClick={handleWishlist}
          aria-label="Wishlist"
        >
          {wishlisted ? '♥' : '♡'}
        </button>
      </Link>

      <div className="card-body">
        <p className="card-category">{product.category}</p>
        <Link to={`/product/${product._id}`}>
          <h3 className="card-name">{product.name}</h3>
        </Link>

        {product.numReviews > 0 && (
          <div className="card-rating">
            <Stars rating={product.rating} />
            <span>({product.numReviews})</span>
          </div>
        )}

        <div className="card-footer">
          <div className="card-price">
            <span className="price-current">{formatPrice(product.price)}</span>
            {product.originalPrice && (
              <span className="price-original">{formatPrice(product.originalPrice)}</span>
            )}
          </div>
          <button
            className="btn btn-primary btn-sm add-btn"
            onClick={handleAdd}
            disabled={product.stock === 0}
          >
            {product.stock === 0 ? 'Sold Out' : '+ Add'}
          </button>
        </div>
      </div>
    </div>
  )
}

export function ProductCardSkeleton() {
  return (
    <div className="product-card skeleton-card">
      <div className="skeleton" style={{ height: '220px', borderRadius: '8px 8px 0 0' }} />
      <div className="card-body">
        <div className="skeleton" style={{ height: '12px', width: '60px', marginBottom: '8px' }} />
        <div className="skeleton" style={{ height: '16px', width: '90%', marginBottom: '6px' }} />
        <div className="skeleton" style={{ height: '16px', width: '70%', marginBottom: '12px' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div className="skeleton" style={{ height: '20px', width: '70px' }} />
          <div className="skeleton" style={{ height: '30px', width: '60px', borderRadius: '4px' }} />
        </div>
      </div>
    </div>
  )
}
