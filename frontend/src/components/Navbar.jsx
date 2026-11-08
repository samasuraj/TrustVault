import React from 'react';
import { Shield, FileText, Upload, ShieldAlert, LogOut, User } from 'lucide-react';

export default function Navbar({ user, activeTab, onTabChange, onOpenUpload, onLogout }) {
  const isOwnerOrAdmin = user && (user.role === 'owner' || user.role === 'admin');
  const isAdmin = user && user.role === 'admin';

  return (
    <header className="navbar">
      <div className="navbar-container">
        <div className="navbar-brand" onClick={() => onTabChange('documents')} role="button" tabIndex={0}>
          <Shield className="brand-icon" />
          <div className="brand-text">
            <span className="brand-title">TrustVault</span>
            <span className="brand-subtitle">Provable Audit Trail</span>
          </div>
        </div>

        <nav className="navbar-nav">
          <button
            type="button"
            className={`nav-link ${activeTab === 'documents' ? 'active' : ''}`}
            onClick={() => onTabChange('documents')}
          >
            <FileText size={18} />
            <span>Documents</span>
          </button>

          {isOwnerOrAdmin && (
            <button
              type="button"
              className="nav-link nav-btn-upload"
              onClick={onOpenUpload}
            >
              <Upload size={18} />
              <span>Upload Document</span>
            </button>
          )}

          {isAdmin && (
            <button
              type="button"
              className={`nav-link ${activeTab === 'admin' ? 'active' : ''}`}
              onClick={() => onTabChange('admin')}
            >
              <ShieldAlert size={18} />
              <span>Admin Console</span>
            </button>
          )}
        </nav>

        <div className="navbar-user">
          <div className="user-info">
            <div className="user-name-row">
              <User size={14} />
              <span className="user-name">{user.name}</span>
              <span className={`badge-pill badge-${user.role}`}>{user.role}</span>
            </div>
            <span className="user-email">{user.email}</span>
          </div>

          <button
            type="button"
            className="btn btn-outline btn-sm btn-logout"
            onClick={onLogout}
            title="Sign Out"
          >
            <LogOut size={16} />
            <span>Sign Out</span>
          </button>
        </div>
      </div>
    </header>
  );
}
