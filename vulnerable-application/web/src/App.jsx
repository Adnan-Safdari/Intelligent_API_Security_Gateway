import { BrowserRouter, Routes, Route, ScrollRestoration } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { AuthProvider } from './context/AuthContext'
import { CartProvider } from './context/CartContext'
import { WishlistProvider } from './context/WishlistContext'
import Navbar from './components/layout/Navbar'
import Footer from './components/layout/Footer'
import ProtectedRoute from './components/common/ProtectedRoute'

import Home from './pages/Home'
import Shop from './pages/Shop'
import ProductPage from './pages/ProductPage'
import Cart from './pages/Cart'
import Checkout from './pages/Checkout'
import Auth from './pages/Auth'
import Orders, { OrderDetail } from './pages/Orders'
import Wishlist from './pages/Wishlist'
import Admin from './pages/Admin'

function ScrollToTop() {
  if (typeof window !== 'undefined') {
    window.scrollTo(0, 0)
  }
  return null
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <CartProvider>
          <WishlistProvider>
            <Toaster
              position="top-right"
              toastOptions={{
                duration: 3000,
                style: {
                  fontFamily: 'DM Sans, sans-serif',
                  fontSize: '0.875rem',
                  borderRadius: '8px',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                },
              }}
            />
            <Navbar />
            <main>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/shop" element={<Shop />} />
                <Route path="/product/:id" element={<ProductPage />} />
                <Route path="/cart" element={<Cart />} />
                <Route path="/login" element={<Auth />} />
                <Route path="/register" element={<Auth />} />
                <Route path="/checkout" element={
                  <ProtectedRoute><Checkout /></ProtectedRoute>
                } />
                <Route path="/orders" element={
                  <ProtectedRoute><Orders /></ProtectedRoute>
                } />
                <Route path="/orders/:id" element={
                  <ProtectedRoute><OrderDetail /></ProtectedRoute>
                } />
                <Route path="/wishlist" element={
                  <ProtectedRoute><Wishlist /></ProtectedRoute>
                } />
                <Route path="/admin" element={
                  <ProtectedRoute><Admin /></ProtectedRoute>
                } />
                <Route path="*" element={
                  <div className="container" style={{ padding: '80px 0', textAlign: 'center' }}>
                    <h1 style={{ fontSize: '4rem', fontWeight: 700, color: 'var(--border)', marginBottom: '16px' }}>404</h1>
                    <p style={{ color: 'var(--text-muted)', marginBottom: '24px' }}>This page doesn't exist.</p>
                    <a href="/" className="btn btn-primary">← Go Home</a>
                  </div>
                } />
              </Routes>
            </main>
            <Footer />
          </WishlistProvider>
        </CartProvider>
      </AuthProvider>
    </BrowserRouter>
  )
}
