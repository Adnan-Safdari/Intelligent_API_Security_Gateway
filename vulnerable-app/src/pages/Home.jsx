import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { productApi } from '../services/api'
import ProductCard, { ProductCardSkeleton } from '../components/common/ProductCard'
import { range } from '../utils'
import './Home.css'

const CATEGORIES = [
  { name: 'Electronics', emoji: '🎧', slug: 'Electronics' },
  { name: 'Clothing', emoji: '👕', slug: 'Clothing' },
  { name: 'Home & Garden', emoji: '🪴', slug: 'Home+%26+Garden' },
  { name: 'Sports', emoji: '🏃', slug: 'Sports' },
  { name: 'Books', emoji: '📚', slug: 'Books' },
  { name: 'Beauty', emoji: '✨', slug: 'Beauty' },
]

export default function Home() {
  const navigate = useNavigate()
  const [featured, setFeatured] = useState([])
  const [allProducts, setAllProducts] = useState([])
  const [loadingFeatured, setLoadingFeatured] = useState(true)
  const [loadingAll, setLoadingAll] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    productApi.getAll({ featured: true, limit: 4 })
      .then((d) => setFeatured(d.products))
      .finally(() => setLoadingFeatured(false))

    // The whole catalogue from the real backend, first eight shown here.
    productApi.getAllProducts()
      .then((d) => setAllProducts(d.products.slice(0, 8)))
      .finally(() => setLoadingAll(false))
  }, [])

  const handleSearch = (e) => {
    e.preventDefault()
    if (searchQuery.trim()) navigate(`/shop?search=${encodeURIComponent(searchQuery.trim())}`)
  }

  return (
    <div className="home">
      {/* Hero */}
      <section className="hero">
        <div className="hero-content container">
          <div className="hero-text">
            <p className="hero-eyebrow">Free shipping on orders over $50</p>
            <h1 className="hero-title">
              Goods you'll<br />
              <span>actually use.</span>
            </h1>
            <p className="hero-sub">
              No hype, no dropshipping. Just curated products tested by real people.
            </p>
            <form className="hero-search" onSubmit={handleSearch}>
              <input
                type="text"
                placeholder="What are you looking for?"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <button type="submit" className="btn btn-primary">Search</button>
            </form>
            <div className="hero-cta">
              <Link to="/shop" className="btn btn-primary btn-lg">Shop All Products</Link>
              <Link to="/products" className="btn btn-secondary btn-lg">All Products</Link>
            </div>
          </div>
          <div className="hero-visual">
            <div className="hero-img-grid">
              <img src="https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=300" alt="headphones" />
              <img src="https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300" alt="tee" />
              <img src="https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=300" alt="coffee" />
              <img src="https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300" alt="wallet" />
            </div>
          </div>
        </div>
      </section>

      {/* Categories */}
      <section className="section-cats">
        <div className="container">
          <h2 className="section-title">Browse Categories</h2>
          <div className="cats-grid">
            {CATEGORIES.map((cat) => (
              <Link key={cat.slug} to={`/shop?category=${cat.slug}`} className="cat-chip">
                <span className="cat-emoji">{cat.emoji}</span>
                <span>{cat.name}</span>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Featured */}
      <section className="section-products">
        <div className="container">
          <div className="section-header">
            <h2 className="section-title">Featured Picks</h2>
            <Link to="/shop?featured=true" className="see-all">See all →</Link>
          </div>
          <div className="product-grid">
            {loadingFeatured
              ? range(4).map((i) => <ProductCardSkeleton key={i} />)
              : featured.map((p) => <ProductCard key={p._id} product={p} />)}
          </div>
        </div>
      </section>

      {/* Promo banner */}
      <section className="promo-banner">
        <div className="container">
          <div className="promo-inner">
            <div>
              <h3>Free shipping on orders $50+</h3>
              <p>Easy 30-day returns. No questions asked.</p>
            </div>
            <Link to="/shop" className="btn btn-primary">Start Shopping</Link>
          </div>
        </div>
      </section>

      {/* All Products */}
      <section className="section-products">
        <div className="container">
          <div className="section-header">
            <h2 className="section-title">All Products</h2>
            <Link to="/products" className="see-all">See all →</Link>
          </div>
          <div className="product-grid">
            {loadingAll
              ? range(8).map((i) => <ProductCardSkeleton key={i} />)
              : allProducts.map((p) => <ProductCard key={p._id} product={p} />)}
          </div>
        </div>
      </section>

      {/* Trust row */}
      <section className="trust-row">
        <div className="container">
          <div className="trust-grid">
            {[
              { icon: '🚚', title: 'Fast Shipping', text: 'Orders ship within 1–2 business days' },
              { icon: '↩️', title: 'Easy Returns', text: '30-day hassle-free return policy' },
              { icon: '🔒', title: 'Secure Checkout', text: 'Your payment info is always encrypted' },
              { icon: '💬', title: 'Real Support', text: 'Actual humans respond Mon–Fri' },
            ].map((t) => (
              <div key={t.title} className="trust-item">
                <span className="trust-icon">{t.icon}</span>
                <div>
                  <strong>{t.title}</strong>
                  <p>{t.text}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}
