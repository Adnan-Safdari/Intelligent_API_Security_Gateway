import { useState, useRef, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'
import { useCart } from '../../context/CartContext'
import { useDebounce } from '../../hooks'
import './Navbar.css'

export default function Navbar() {
  const { user, logout } = useAuth()
  const { totalItems } = useCart()
  const navigate = useNavigate()
  const location = useLocation()

  const [search, setSearch] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const [attackBlocked, setAttackBlocked] = useState(false)

  const debouncedSearch = useDebounce(search, 400)
  const userMenuRef = useRef(null)

  useEffect(() => {
    if (debouncedSearch.trim()) {
      navigate(`/shop?search=${encodeURIComponent(debouncedSearch.trim())}`)
    }
  }, [debouncedSearch, navigate])

  useEffect(() => {
    if (typeof window === 'undefined' || !window.__ATTACK_BLOCKED__) {
      return
    }

    setAttackBlocked(true)

    const timer = setTimeout(() => {
      window.__ATTACK_BLOCKED__ = false
      setAttackBlocked(false)
    }, 3000)

    return () => clearTimeout(timer)
  }, [location.pathname])

  useEffect(() => {
    const handler = (e) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) {
        setUserMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    setMenuOpen(false)
  }, [location.pathname])

  const handleLogout = () => {
    logout()
    setUserMenuOpen(false)
    navigate('/')
  }

  return (
    <>
      {attackBlocked && (
        <div style={{
          background: '#ff4d4f',
          color: 'white',
          padding: '10px',
          textAlign: 'center',
          fontWeight: 'bold',
          letterSpacing: '0.5px',
        }}>
          ATTACK BLOCKED: SQL Injection detected
        </div>
      )}

      <header className="navbar">
        <div className="navbar-inner container-wide">
          <Link to="/" className="navbar-logo">
            <span className="logo-icon">⬡</span>
            ShopForge
          </Link>

          <div className="navbar-search">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.35-4.35" />
            </svg>
            <input
              type="search"
              placeholder="Search products..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && search.trim() && navigate(`/shop?search=${encodeURIComponent(search.trim())}`)}
            />
          </div>

          <nav className={`navbar-nav ${menuOpen ? 'open' : ''}`}>
            <Link to="/shop" className="nav-link">Shop</Link>
            <Link to="/shop?newArrival=true" className="nav-link">New Arrivals</Link>

            {user ? (
              <div className="user-menu" ref={userMenuRef}>
                <button className="user-btn" onClick={() => setUserMenuOpen((p) => !p)}>
                  <span className="user-avatar">{user.name?.[0]?.toUpperCase() || 'U'}</span>
                  <span className="user-name">{user.name?.split(' ')[0] || 'User'}</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="m6 9 6 6 6-6" />
                  </svg>
                </button>
                {userMenuOpen && (
                  <div className="user-dropdown">
                    <Link to="/orders" onClick={() => setUserMenuOpen(false)}>My Orders</Link>
                    <Link to="/wishlist" onClick={() => setUserMenuOpen(false)}>Wishlist</Link>
                    {user.isAdmin && <Link to="/admin" onClick={() => setUserMenuOpen(false)}>Admin Panel</Link>}
                    <div className="dropdown-divider" />
                    <button onClick={handleLogout}>Sign Out</button>
                  </div>
                )}
              </div>
            ) : (
              <Link to="/login" className="nav-link">Sign In</Link>
            )}

            <Link to="/cart" className="cart-btn">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z" />
                <line x1="3" y1="6" x2="21" y2="6" />
                <path d="M16 10a4 4 0 0 1-8 0" />
              </svg>
              {totalItems > 0 && <span className="cart-badge">{totalItems}</span>}
            </Link>
          </nav>

          <button className="hamburger" onClick={() => setMenuOpen((p) => !p)} aria-label="Menu">
            <span />
            <span />
            <span />
          </button>
        </div>
      </header>
    </>
  )
}