import { useEffect, useState } from 'react'

export default function App() {
  const [health, setHealth] = useState(null)
  const [err, setErr] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/health')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP error ${res.status}`)
        return res.json()
      })
      .then((data) => {
        setHealth(data)
        setLoading(false)
      })
      .catch((e) => {
        setErr(e.message)
        setLoading(false)
      })
  }, [])

  return (
    <div className="container">
      <header className="header">
        <div className="brand">
          <svg className="brand-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
            <path d="m7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          <div>
            <h1>TrustVault</h1>
          </div>
          <span className="brand-badge">Provable Audit Trail</span>
        </div>
      </header>

      <div className="card">
        <h2 className="card-title">System Status</h2>
        <div className="grid">
          <div className="stat-box">
            <div className="stat-label">API Health</div>
            <div className="stat-value">
              {loading && <span>Checking...</span>}
              {!loading && !err && <span className="badge-ok">● Connected</span>}
              {!loading && err && <span className="badge-err">● Offline ({err})</span>}
            </div>
          </div>

          <div className="stat-box">
            <div className="stat-label">PostgreSQL Database</div>
            <div className="stat-value">
              {loading && <span>Checking...</span>}
              {!loading && health?.db && <span className="badge-ok">● Online (PostgreSQL 16)</span>}
              {!loading && (!health || !health.db) && <span className="badge-err">● Degraded</span>}
            </div>
          </div>

          <div className="stat-box">
            <div className="stat-label">Platform Stack</div>
            <div className="stat-value" style={{ fontSize: '1rem', color: '#334155' }}>
              FastAPI + SQLAlchemy 2 + React
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title">Non-Negotiable Security Policies</h2>
        <div className="rules-list">
          <div className="rule-item">
            <span className="rule-number">1</span>
            <div className="rule-text"><strong>Centralized Authorization:</strong> Every route touching a document calls <code>authorize()</code> from <code>app/authz.py</code>.</div>
          </div>
          <div className="rule-item">
            <span className="rule-number">2</span>
            <div className="rule-text"><strong>Deny by Default & Anti-Enumeration:</strong> Unauthorized access returns 404 to avoid leaking document existence.</div>
          </div>
          <div className="rule-item">
            <span className="rule-number">3</span>
            <div className="rule-text"><strong>Audited Decisions:</strong> Every decision (allowed and denied) writes a hash-chained audit record.</div>
          </div>
          <div className="rule-item">
            <span className="rule-number">4</span>
            <div className="rule-text"><strong>Encrypted At Rest:</strong> Files stored under random UUID names outside web root, streamed via authenticated endpoints.</div>
          </div>
          <div className="rule-item">
            <span className="rule-number">5</span>
            <div className="rule-text"><strong>Instant Revocation:</strong> Revocation takes effect on next request with zero permission caching.</div>
          </div>
          <div className="rule-item">
            <span className="rule-number">6</span>
            <div className="rule-text"><strong>Append-Only Audit Trail:</strong> DB triggers strictly forbid UPDATE and DELETE on audit events.</div>
          </div>
        </div>
      </div>
    </div>
  )
}
