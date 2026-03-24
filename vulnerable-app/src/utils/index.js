export const formatPrice = (n) =>
  new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(n)

export const formatDate = (d) =>
  new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })

export const truncate = (str, n = 80) => (str.length > n ? str.slice(0, n) + '…' : str)

export const discount = (original, current) =>
  original ? Math.round(((original - current) / original) * 100) : 0

export const range = (n) => [...Array(n).keys()]

export const clamp = (val, min, max) => Math.min(Math.max(val, min), max)
