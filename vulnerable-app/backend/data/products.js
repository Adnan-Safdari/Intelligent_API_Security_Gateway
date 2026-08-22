// Seed catalog for the products table.
//
// Kept here rather than inline in db.js so the list is easy to read and grow.
// Columns are snake_case to match the table; the /api/products route reshapes
// them into the camelCase shape the storefront's ProductCard expects
// (images[], originalPrice, numReviews, isNewArrival).

const PRODUCTS = [
  {
    name: 'Wireless Noise-Cancelling Headphones',
    description: 'Premium over-ear headphones with active noise cancellation and 30-hour battery life.',
    price: 89.99, original_price: 129.99, category: 'Electronics',
    image: 'https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=700',
    stock: 45, rating: 4.3, num_reviews: 128, is_new_arrival: false,
  },
  {
    name: 'Classic Cotton Crew Neck Tee',
    description: 'Soft, breathable 100% cotton t-shirt with a relaxed fit. A wardrobe staple.',
    price: 24.99, original_price: 34.99, category: 'Clothing',
    image: 'https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=700',
    stock: 210, rating: 4.6, num_reviews: 342, is_new_arrival: true,
  },
  {
    name: 'Stainless Steel Water Bottle',
    description: 'Double-walled vacuum insulation keeps drinks cold for 24 hours or hot for 12.',
    price: 19.99, original_price: 29.99, category: 'Home',
    image: 'https://images.unsplash.com/photo-1602143407151-7111542de6e8?w=700',
    stock: 178, rating: 4.7, num_reviews: 256, is_new_arrival: false,
  },
  {
    name: 'Mechanical Keyboard - RGB Backlit',
    description: 'Tactile mechanical switches, per-key RGB, and a detachable USB-C cable.',
    price: 74.99, original_price: 99.99, category: 'Electronics',
    image: 'https://images.unsplash.com/photo-1587829741301-dc798b83add3?w=700',
    stock: 62, rating: 4.5, num_reviews: 189, is_new_arrival: true,
  },
  {
    name: 'Leather Weekender Bag',
    description: 'Full-grain leather travel bag with a spacious main compartment and shoulder strap.',
    price: 149.99, original_price: 199.99, category: 'Accessories',
    image: 'https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=700',
    stock: 34, rating: 4.8, num_reviews: 97, is_new_arrival: false,
  },
  {
    name: 'Ceramic Pour-Over Coffee Set',
    description: 'Hand-glazed ceramic dripper and carafe for a clean, bright cup of coffee.',
    price: 39.99, original_price: 54.99, category: 'Home',
    image: 'https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=700',
    stock: 88, rating: 4.4, num_reviews: 143, is_new_arrival: true,
  },
  {
    name: 'Running Shoes - Lightweight',
    description: 'Breathable mesh upper with responsive foam cushioning for everyday runs.',
    price: 64.99, original_price: 89.99, category: 'Footwear',
    image: 'https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=700',
    stock: 120, rating: 4.2, num_reviews: 311, is_new_arrival: false,
  },
  {
    name: 'Smart Fitness Watch',
    description: 'Heart-rate tracking, GPS, and a 7-day battery in a slim aluminium case.',
    price: 129.99, original_price: 179.99, category: 'Electronics',
    image: 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=700',
    stock: 54, rating: 4.5, num_reviews: 402, is_new_arrival: true,
  },
  {
    name: 'Organic Scented Candle',
    description: 'Soy wax candle with essential-oil fragrance and a 50-hour burn time.',
    price: 16.99, original_price: 22.99, category: 'Home',
    image: 'https://images.unsplash.com/photo-1602874801007-bd458bb1b8b6?w=700',
    stock: 240, rating: 4.6, num_reviews: 178, is_new_arrival: false,
  },
  {
    name: 'Denim Trucker Jacket',
    description: 'Classic mid-wash denim jacket with a tailored fit and durable stitching.',
    price: 79.99, original_price: 109.99, category: 'Clothing',
    image: 'https://images.unsplash.com/photo-1543076447-215ad9ba6923?w=700',
    stock: 76, rating: 4.4, num_reviews: 134, is_new_arrival: true,
  },
  {
    name: 'Wireless Charging Pad',
    description: 'Fast 15W Qi charging with a non-slip surface and status LED.',
    price: 29.99, original_price: 44.99, category: 'Electronics',
    image: 'https://images.unsplash.com/photo-1591290619762-b0c9c1f6f5f4?w=700',
    stock: 143, rating: 4.1, num_reviews: 88, is_new_arrival: false,
  },
  {
    name: 'Polarized Aviator Sunglasses',
    description: 'UV400 polarized lenses in a lightweight metal frame with spring hinges.',
    price: 34.99, original_price: 49.99, category: 'Accessories',
    image: 'https://images.unsplash.com/photo-1511499767150-a48a237f0083?w=700',
    stock: 165, rating: 4.3, num_reviews: 220, is_new_arrival: true,
  },
];

module.exports = { PRODUCTS };
