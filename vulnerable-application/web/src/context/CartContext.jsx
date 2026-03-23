import { createContext, useContext, useState, useEffect } from 'react'

const CartContext = createContext(null)

export function CartProvider({ children }) {
  const [items, setItems] = useState(() => {
    try { return JSON.parse(localStorage.getItem('sf_cart') || '[]') } catch { return [] }
  })

  useEffect(() => {
    localStorage.setItem('sf_cart', JSON.stringify(items))
  }, [items])

  const addToCart = (product, quantity = 1) => {
    setItems((prev) => {
      const existing = prev.find((i) => i._id === product._id)
      if (existing) {
        return prev.map((i) =>
          i._id === product._id
            ? { ...i, quantity: Math.min(i.quantity + quantity, product.stock) }
            : i
        )
      }
      return [...prev, { ...product, quantity }]
    })
  }

  const removeFromCart = (id) => setItems((prev) => prev.filter((i) => i._id !== id))

  const updateQuantity = (id, quantity) => {
    if (quantity < 1) return removeFromCart(id)
    setItems((prev) => prev.map((i) => (i._id === id ? { ...i, quantity } : i)))
  }

  const clearCart = () => setItems([])

  const totalItems = items.reduce((sum, i) => sum + i.quantity, 0)
  const subtotal = items.reduce((sum, i) => sum + i.price * i.quantity, 0)

  return (
    <CartContext.Provider value={{ items, addToCart, removeFromCart, updateQuantity, clearCart, totalItems, subtotal }}>
      {children}
    </CartContext.Provider>
  )
}

export const useCart = () => useContext(CartContext)
