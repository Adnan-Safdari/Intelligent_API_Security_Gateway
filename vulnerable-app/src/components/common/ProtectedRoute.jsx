import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../../context/AuthContext'

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) return (
    <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
      <span className="spinner spinner-lg" />
    </div>
  )

  if (!user) return <Navigate to="/login" state={{ from: location.pathname }} replace />

  return children
}
