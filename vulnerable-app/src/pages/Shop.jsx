import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { productApi } from '../services/api'
import ProductCard, { ProductCardSkeleton } from '../components/common/ProductCard'
import Pagination from '../components/common/Pagination'
import { range } from '../utils'
import './Shop.css'

const CATEGORIES = ['Electronics', 'Clothing', 'Home & Garden', 'Sports', 'Books', 'Toys', 'Beauty', 'Food']
const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest First' },
  { value: 'price_asc', label: 'Price: Low to High' },
  { value: 'price_desc', label: 'Price: High to Low' },
  { value: 'rating', label: 'Top Rated' },
]

export default function Shop() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [products, setProducts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(1)
  const [pages, setPages] = useState(1)
  const [total, setTotal] = useState(0)
  const [sidebarOpen, setSidebarOpen] = useState(false)

  // Filters from URL
  const category = searchParams.get('category') || ''
  const search = searchParams.get('search') || ''
  const sort = searchParams.get('sort') || 'newest'
  const minPrice = searchParams.get('minPrice') || ''
  const maxPrice = searchParams.get('maxPrice') || ''
  const rating = searchParams.get('rating') || ''
  const newArrival = searchParams.get('newArrival') || ''

  // Local draft filters
  const [draftMin, setDraftMin] = useState(minPrice)
  const [draftMax, setDraftMax] = useState(maxPrice)

  const fetchProducts = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params = { page, limit: 12 }
      if (category) params.category = category
      if (search) params.search = search
      if (sort) params.sort = sort
      if (minPrice) params.minPrice = minPrice
      if (maxPrice) params.maxPrice = maxPrice
      if (rating) params.rating = rating
      if (newArrival) params.newArrival = newArrival

      const data = await productApi.getAll(params)
      setProducts(data.products)
      setPages(data.pages)
      setTotal(data.total)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [page, category, search, sort, minPrice, maxPrice, rating, newArrival])

  useEffect(() => { fetchProducts() }, [fetchProducts])
  useEffect(() => { setPage(1) }, [category, search, sort, minPrice, maxPrice, rating, newArrival])

  const setParam = (key, value) => {
    const params = Object.fromEntries(searchParams)
    if (value) params[key] = value
    else delete params[key]
    setSearchParams(params)
  }

  const applyPriceFilter = () => {
    const params = Object.fromEntries(searchParams)
    if (draftMin) params.minPrice = draftMin; else delete params.minPrice
    if (draftMax) params.maxPrice = draftMax; else delete params.maxPrice
    setSearchParams(params)
  }

  const clearAllFilters = () => {
    setDraftMin('')
    setDraftMax('')
    setSearchParams({})
  }

  const hasFilters = category || search || minPrice || maxPrice || rating || newArrival

  return (
    <div className="shop-page container">
      <div className="shop-top">
        <div>
          <h1 className="shop-heading">
            {search ? `Results for "${search}"` : category || 'All Products'}
          </h1>
          <p className="shop-count">{total} products</p>
        </div>
        <div className="shop-controls">
          <button className="btn btn-secondary btn-sm filter-toggle" onClick={() => setSidebarOpen((p) => !p)}>
            ⚙ Filters {hasFilters ? '●' : ''}
          </button>
          <select
            className="form-select"
            value={sort}
            onChange={(e) => setParam('sort', e.target.value)}
          >
            {SORT_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
      </div>

      <div className="shop-layout">
        {/* Sidebar */}
        <aside className={`shop-sidebar ${sidebarOpen ? 'open' : ''}`}>
          <div className="sidebar-section">
            <h3>Category</h3>
            <ul className="filter-list">
              <li>
                <button className={!category ? 'active' : ''} onClick={() => setParam('category', '')}>All</button>
              </li>
              {CATEGORIES.map((c) => (
                <li key={c}>
                  <button
                    className={category === c ? 'active' : ''}
                    onClick={() => setParam('category', category === c ? '' : c)}
                  >{c}</button>
                </li>
              ))}
            </ul>
          </div>

          <div className="sidebar-section">
            <h3>Price Range</h3>
            <div className="price-inputs">
              <input
                type="number"
                placeholder="Min $"
                className="form-input"
                value={draftMin}
                onChange={(e) => setDraftMin(e.target.value)}
                min="0"
              />
              <span>—</span>
              <input
                type="number"
                placeholder="Max $"
                className="form-input"
                value={draftMax}
                onChange={(e) => setDraftMax(e.target.value)}
                min="0"
              />
            </div>
            <button className="btn btn-secondary btn-sm w-full mt-2" onClick={applyPriceFilter}>
              Apply Price
            </button>
          </div>

          <div className="sidebar-section">
            <h3>Min Rating</h3>
            <ul className="filter-list">
              {['', '4', '3', '2'].map((r) => (
                <li key={r}>
                  <button
                    className={rating === r ? 'active' : ''}
                    onClick={() => setParam('rating', r)}
                  >
                    {r ? `${r}★ & up` : 'Any rating'}
                  </button>
                </li>
              ))}
            </ul>
          </div>

          <div className="sidebar-section">
            <h3>Arrivals</h3>
            <ul className="filter-list">
              <li><button className={!newArrival ? 'active' : ''} onClick={() => setParam('newArrival', '')}>All</button></li>
              <li><button className={newArrival === 'true' ? 'active' : ''} onClick={() => setParam('newArrival', newArrival === 'true' ? '' : 'true')}>New Arrivals Only</button></li>
            </ul>
          </div>

          {hasFilters && (
            <button className="btn btn-ghost btn-sm w-full" onClick={clearAllFilters}>
              ✕ Clear all filters
            </button>
          )}
        </aside>

        {/* Product grid */}
        <main className="shop-main">
          {error && (
            <div className="error-box">
              ⚠ {error}
              <button onClick={fetchProducts} style={{ marginLeft: 'auto', fontWeight: 600, cursor: 'pointer' }}>Retry</button>
            </div>
          )}

          {!loading && !error && products.length === 0 && (
            <div className="empty-state">
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
              </svg>
              <h3>No products found</h3>
              <p>Try adjusting your filters or search query.</p>
              <button className="btn btn-secondary mt-4" onClick={clearAllFilters}>Clear Filters</button>
            </div>
          )}

          <div className="product-grid">
            {loading
              ? range(12).map((i) => <ProductCardSkeleton key={i} />)
              : products.map((p) => <ProductCard key={p._id} product={p} />)
            }
          </div>

          <Pagination page={page} pages={pages} onPage={(p) => { setPage(p); window.scrollTo(0, 0) }} />
        </main>
      </div>
    </div>
  )
}
