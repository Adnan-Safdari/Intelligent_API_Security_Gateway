import { createContext, useContext, useState, useEffect } from 'react'
import { userApi } from '../services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('sf_token')
    const stored = localStorage.getItem('sf_user')
    if (token && stored) {
      try { setUser(JSON.parse(stored)) } catch {}
    }
    setLoading(false)
  }, [])

  const login = async (email, password) => {
    const data = await userApi.login({ email, password })
    localStorage.setItem('sf_token', data.token)
    localStorage.setItem('sf_user', JSON.stringify(data.user))
    setUser(data.user)
    return data.user
  }

  const register = async (name, email, password) => {
    const data = await userApi.register({ name, email, password })
    localStorage.setItem('sf_token', data.token)
    localStorage.setItem('sf_user', JSON.stringify(data.user))
    setUser(data.user)
    return data.user
  }

  const logout = () => {
    localStorage.removeItem('sf_token')
    localStorage.removeItem('sf_user')
    setUser(null)
  }

  const updateUser = (updated) => {
    localStorage.setItem('sf_user', JSON.stringify(updated))
    setUser(updated)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, updateUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
