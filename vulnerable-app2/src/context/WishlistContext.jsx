import { createContext, useContext, useState, useEffect } from 'react'
import { userApi } from '../services/api'
import { useAuth } from './AuthContext'

const WishlistContext = createContext(null)

export function WishlistProvider({ children }) {
  const { user } = useAuth()
  const [wishlist, setWishlist] = useState([])

  useEffect(() => {
    if (user) {
      userApi.getWishlist().then((data) => setWishlist(data.map((p) => p._id || p))).catch(() => {})
    } else {
      setWishlist([])
    }
  }, [user])

  const toggleWishlist = async (productId) => {
    if (!user) return false
    try {
      const data = await userApi.toggleWishlist(productId)
      setWishlist(data.wishlist.map((id) => id.toString()))
      return true
    } catch {
      return false
    }
  }

  const isWishlisted = (productId) => wishlist.includes(productId?.toString())

  return (
    <WishlistContext.Provider value={{ wishlist, toggleWishlist, isWishlisted }}>
      {children}
    </WishlistContext.Provider>
  )
}

export const useWishlist = () => useContext(WishlistContext)
