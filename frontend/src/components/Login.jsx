import React, { useState } from 'react';
import { authApi } from '../api';
import { Shield, Lock, Mail, AlertCircle, UserCheck } from 'lucide-react';

const isDev = import.meta.env.DEV;

const SEED_ACCOUNTS = isDev
  ? [
      { role: 'admin', label: 'Admin', email: 'admin@trustvault.local', pw: 'AdminPassword123!' },
      { role: 'owner', label: 'Alice (Owner)', email: 'alice.owner@trustvault.local', pw: 'AlicePassword123!' },
      { role: 'owner', label: 'Bob (Owner)', email: 'bob.owner@trustvault.local', pw: 'BobPassword123!' },
      { role: 'viewer', label: 'Charlie (Viewer)', email: 'charlie.viewer@trustvault.local', pw: 'CharliePassword123!' },
    ]
  : [];

export default function Login({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setErr('');
    setLoading(true);
    try {
      const user = await authApi.login(email.trim(), password);
      onLoginSuccess(user);
    } catch (e) {
      setErr(e.message || 'Login failed. Please check credentials.');
    } finally {
      setLoading(false);
    }
  }

  function handleQuickFill(acc) {
    setEmail(acc.email);
    setPassword(acc.pw);
    setErr('');
  }

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <div className="login-header">
          <div className="brand-icon-box">
            <Shield className="brand-icon-lg" />
          </div>
          <h2>Sign in to TrustVault</h2>
          <p className="subtitle">Secure Document Sharing with Provable Audit Trail</p>
        </div>

        {err && (
          <div className="alert alert-error">
            <AlertCircle size={18} />
            <span>{err}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="form-group">
          <div className="input-group">
            <label htmlFor="email">Email Address</label>
            <div className="input-field-wrap">
              <Mail className="input-icon" size={18} />
              <input
                id="email"
                type="email"
                required
                placeholder="name@organization.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
              />
            </div>
          </div>

          <div className="input-group">
            <label htmlFor="password">Password</label>
            <div className="input-field-wrap">
              <Lock className="input-icon" size={18} />
              <input
                id="password"
                type="password"
                required
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </div>
          </div>

          <button type="submit" disabled={loading} className="btn btn-primary btn-block">
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        {isDev && SEED_ACCOUNTS.length > 0 && (
          <div className="demo-accounts-section">
            <div className="demo-title">
              <UserCheck size={14} /> Quick Demo Accounts
            </div>
            <div className="demo-grid">
              {SEED_ACCOUNTS.map((acc) => (
                <button
                  key={acc.email}
                  type="button"
                  className="btn-demo"
                  onClick={() => handleQuickFill(acc)}
                >
                  <span className={`badge-pill badge-${acc.role}`}>{acc.role}</span>
                  <span className="demo-name">{acc.label}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
