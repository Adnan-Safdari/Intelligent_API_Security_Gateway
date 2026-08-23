import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { productApi } from '../services/api'
import ProductCard, { ProductCardSkeleton } from '../components/common/ProductCard'
import { range } from '../utils'
import './Home.css'

// The whole catalogue, from the real backend (GET /api/products). Unlike Shop,
// which filters the in-memory mock, this page is the storefront's view of the
// live products endpoint -- so it is also what a flood of /api/products in the
// gateway demo is actually hitting.
export default function AllProducts() {
  const [searchParams, setSearchParams] = useSearchParams()
  const search = searchParams.get('search') || ''

  const [products, setProducts] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState(search)

  useEffect(() => {
    let live = true
    setLoading(true)
    productApi.getAllProducts({ search })
      .then((d) => {
        if (!live) return
        setProducts(d.products)
        setTotal(d.total)
      })
      .finally(() => live && setLoading(false))
    return () => { live = false }
  }, [search])

  const submitSearch = (e) => {
    e.preventDefault()
    const next = query.trim()
    setSearchParams(next ? { search: next } : {})
  }

  return (
    <section className="section-products">
      <div className="container">
        <div className="section-header">
          <h1 className="section-title">All Products</h1>
          {!loading ? <span className="see-all">{total} products</span> : null}
        </div>

        <form onSubmit={submitSearch} className="all-products-search" style={{ marginBottom: '1.5rem' }}>
          <input
            type="search"
            className="form-input"
            placeholder="Search all products…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </form>

        {!loading && products.length === 0 ? (
          <div className="empty-state">
            <p>No products found{search ? ` for “${search}”` : ''}.</p>
          </div>
        ) : (
          <div className="product-grid">
            {loading
              ? range(8).map((i) => <ProductCardSkeleton key={i} />)
              : products.map((p) => <ProductCard key={p._id} product={p} />)}
          </div>
        )}
      </div>
    </section>
  )
}
