import './Pagination.css'

export default function Pagination({ page, pages, onPage }) {
  if (pages <= 1) return null

  const items = []
  for (let i = 1; i <= pages; i++) items.push(i)

  return (
    <div className="pagination">
      <button
        className="pg-btn"
        disabled={page === 1}
        onClick={() => onPage(page - 1)}
      >
        ← Prev
      </button>
      <div className="pg-numbers">
        {items.map((i) => (
          <button
            key={i}
            className={`pg-num ${i === page ? 'active' : ''}`}
            onClick={() => onPage(i)}
          >
            {i}
          </button>
        ))}
      </div>
      <button
        className="pg-btn"
        disabled={page === pages}
        onClick={() => onPage(page + 1)}
      >
        Next →
      </button>
    </div>
  )
}
