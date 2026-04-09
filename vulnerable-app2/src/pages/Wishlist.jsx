import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { userApi } from '../services/api'
import ProductCard, { ProductCardSkeleton } from '../components/common/ProductCard'
import { range } from '../utils'

export default function Wishlist() {
  const [products, setProducts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    userApi.getWishlist()
      .then(setProducts)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="container" style={{ padding: '32px 0 60px' }}>
      <div className="page-header"><h1>My Wishlist</h1></div>
      {error && <div className="error-box">⚠ {error}</div>}
      {!loading && products.length === 0 && (
        <div className="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z" />
          </svg>
          <h3>Your wishlist is empty</h3>
          <p style={{ marginBottom: '16px' }}>Save products you love to come back to them later.</p>
          <Link to="/shop" className="btn btn-primary">Browse Products</Link>
        </div>
      )}
      <div className="product-grid">
        {loading ? range(4).map((i) => <ProductCardSkeleton key={i} />) : products.map((p) => <ProductCard key={p._id} product={p} />)}
      </div>
    </div>
  )
}
