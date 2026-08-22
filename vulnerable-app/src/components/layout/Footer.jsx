import { Link } from 'react-router-dom'
import './Footer.css'

export default function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <div className="footer-grid">
          <div className="footer-brand">
            <div className="footer-logo">
              <span>⬡</span> ShopForge
            </div>
            <p>Real goods at fair prices. No nonsense, no gimmicks — just stuff that works.</p>
            <div className="footer-social">
              <a href="#" aria-label="Twitter">𝕏</a>
              <a href="#" aria-label="Instagram">◎</a>
              <a href="#" aria-label="Facebook">ƒ</a>
            </div>
          </div>
          <div className="footer-col">
            <h4>Shop</h4>
            <Link to="/shop">All Products</Link>
            <Link to="/products">All Products</Link>
            <Link to="/shop?category=Electronics">Electronics</Link>
            <Link to="/shop?category=Clothing">Clothing</Link>
            <Link to="/shop?category=Home+%26+Garden">Home & Garden</Link>
          </div>
          <div className="footer-col">
            <h4>Account</h4>
            <Link to="/login">Sign In</Link>
            <Link to="/register">Create Account</Link>
            <Link to="/orders">My Orders</Link>
            <Link to="/wishlist">Wishlist</Link>
          </div>
          <div className="footer-col">
            <h4>Contact</h4>
            <p>123 Maker Street<br />Portland, OR 97201</p>
            <a href="mailto:hello@shopforge.com">hello@shopforge.com</a>
            <a href="tel:+15031234567">+1 (503) 123-4567</a>
            <p className="footer-hours">Mon–Fri, 9am–5pm PT</p>
          </div>
        </div>
        <div className="footer-bottom">
          <p>© {new Date().getFullYear()} ShopForge. All rights reserved.</p>
          <div className="footer-links">
            <a href="#">Privacy Policy</a>
            <a href="#">Terms of Service</a>
            <a href="#">Returns</a>
          </div>
        </div>
      </div>
    </footer>
  )
}
