import React, { useState, useEffect } from 'react';
import { adminApi, authApi } from '../api';
import {
  ShieldAlert, CheckCircle, AlertTriangle, Download, RefreshCw,
  Search, UserPlus, Lock, Ban, RotateCw, Filter, ChevronRight, ChevronDown, Check, X
} from 'lucide-react';

export default function AdminDashboard({ currentUser }) {
  const [activeSubTab, setActiveSubTab] = useState('audit'); // 'audit', 'alerts', 'users', 'activity'

  // Administrative Activity state
  const [activityEvents, setActivityEvents] = useState([]);
  const [activityTotal, setActivityTotal] = useState(0);
  const [activityOffset, setActivityOffset] = useState(0);
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityActionFilter, setActivityActionFilter] = useState('');
  const [activityActorFilter, setActivityActorFilter] = useState('');
  const [activitySinceFilter, setActivitySinceFilter] = useState('');
  // Login history (subset)
  const [loginEvents, setLoginEvents] = useState([]);
  const [loginLoading, setLoginLoading] = useState(false);
  const [activityViewMode, setActivityViewMode] = useState('all'); // 'all' | 'logins'


  // Audit state
  const [auditEvents, setAuditEvents] = useState([]);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditOffset, setAuditOffset] = useState(0);
  const [auditAction, setAuditAction] = useState('');
  const [auditOutcome, setAuditOutcome] = useState('');
  const [auditActor, setAuditActor] = useState('');
  const [auditDoc, setAuditDoc] = useState('');
  const [expandedRow, setExpandedRow] = useState(null);

  // Chain verify state
  const [verifying, setVerifying] = useState(false);
  const [chainResult, setChainResult] = useState(null);

  // Alerts state
  const [alerts, setAlerts] = useState([]);
  const [loadingAlerts, setLoadingAlerts] = useState(false);
  const [activitySummary, setActivitySummary] = useState(null);

  // User management state
  const [regEmail, setRegEmail] = useState('');
  const [regName, setRegName] = useState('');
  const [regPw, setRegPw] = useState('');
  const [regRole, setRegRole] = useState('viewer');
  const [regSuccess, setRegSuccess] = useState('');
  const [regErr, setRegErr] = useState('');
  const [creatingUser, setCreatingUser] = useState(false);

  // Quick user action input
  const [actionUserId, setActionUserId] = useState('');
  const [userActionMsg, setUserActionMsg] = useState('');
  const [userActionErr, setUserActionErr] = useState('');

  useEffect(() => {
    loadAudit();
    loadAlerts();
  }, []);

  async function loadAudit(offset = 0) {
    setLoadingAudit(true);
    try {
      const res = await adminApi.getAuditEvents({
        action: auditAction || undefined,
        outcome: auditOutcome || undefined,
        actor_id: auditActor || undefined,
        doc_id: auditDoc || undefined,
        limit: 25,
        offset: offset,
      });
      setAuditEvents(res.events || []);
      setAuditTotal(res.total || 0);
      setAuditOffset(offset);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAudit(false);
    }
  }

  async function handleVerifyChain() {
    setVerifying(true);
    setChainResult(null);
    try {
      const res = await adminApi.verifyChain();
      setChainResult(res);
    } catch (e) {
      setChainResult({ valid: false, error: e.message });
    } finally {
      setVerifying(false);
    }
  }

  async function loadAlerts() {
    setLoadingAlerts(true);
    try {
      const [alertsRes, actRes] = await Promise.all([
        adminApi.getAlerts().catch(() => ({ alerts: [] })),
        adminApi.getActivity().catch(() => null),
      ]);
      setAlerts(alertsRes.alerts || []);
      setActivitySummary(actRes);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAlerts(false);
    }
  }

  async function handleExportCsv() {
    try {
      await adminApi.exportAuditCsv({
        action: auditAction || undefined,
        outcome: auditOutcome || undefined,
      });
    } catch (e) {
      alert(`CSV export failed: ${e.message}`);
    }
  }

  async function handleRegisterUser(e) {
    e.preventDefault();
    setRegErr('');
    setRegSuccess('');
    setCreatingUser(true);
    try {
      const u = await authApi.registerUser({
        email: regEmail.trim(),
        name: regName.trim(),
        password: regPw,
        role: regRole,
      });
      setRegSuccess(`User registered: ${u.email} (${u.role})`);
      setRegEmail('');
      setRegName('');
      setRegPw('');
    } catch (e) {
      setRegErr(e.message || 'Registration failed.');
    } finally {
      setCreatingUser(false);
    }
  }

  async function handleDisableUser() {
    if (!actionUserId.trim()) return;
    setUserActionErr('');
    setUserActionMsg('');
    try {
      await authApi.disableUser(actionUserId.trim());
      setUserActionMsg(`User ${actionUserId} disabled. All sessions revoked immediately.`);
    } catch (e) {
      setUserActionErr(e.message || 'Action failed.');
    }
  }

  async function handleBumpVersion() {
    if (!actionUserId.trim()) return;
    setUserActionErr('');
    setUserActionMsg('');
    try {
      await authApi.bumpTokenVersion(actionUserId.trim());
      setUserActionMsg(`Token version bumped for ${actionUserId}. Prior JWTs invalidated.`);
    } catch (e) {
      setUserActionErr(e.message || 'Action failed.');
    }
  }

  async function loadUserActivity(offset = 0) {
    setActivityLoading(true);
    try {
      const res = await adminApi.getUserActivity({
        action: activityActionFilter || undefined,
        actor_id: activityActorFilter || undefined,
        since: activitySinceFilter || undefined,
        limit: 50,
        offset,
      });
      setActivityEvents(res.events || []);
      setActivityTotal(res.total || 0);
      setActivityOffset(offset);
    } catch (e) {
      console.error(e);
    } finally {
      setActivityLoading(false);
    }
  }

  async function loadLoginHistory() {
    setLoginLoading(true);
    try {
      const res = await adminApi.getUserActivity({ action: 'auth_login', limit: 100, offset: 0 });
      setLoginEvents(res.events || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoginLoading(false);
    }
  }

  return (

    <div className="admin-view">
      <div className="page-header">
        <div>
          <h2>Admin Console</h2>
          <p className="subtitle">Provable HMAC-SHA256 audit trail verification and system security alerts.</p>
        </div>

        {/* Chain Verify Button */}
        <div className="chain-verify-cta">
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleVerifyChain}
            disabled={verifying}
          >
            <RefreshCw className={verifying ? 'spin-icon' : ''} size={16} />
            <span>{verifying ? 'Verifying HMAC Chain...' : 'Verify Audit Hash Chain'}</span>
          </button>
        </div>
      </div>

      {/* Chain Verify Result Banner */}
      {chainResult && (() => {
        const isValid = Boolean(chainResult.valid ?? chainResult.ok);
        const count = chainResult.total_events || chainResult.verified_events || chainResult.events_verified || 'all';
        return (
          <div className={`chain-result-banner ${isValid ? 'banner-valid' : 'banner-invalid'}`}>
            {isValid ? (
              <div className="banner-content">
                <CheckCircle className="banner-icon-success" size={24} />
                <div>
                  <strong>Audit Chain Cryptographically Intact</strong>
                  <p>
                    Verified {count} audit events. Zero tampering detected.
                  </p>
                </div>
              </div>
            ) : (
              <div className="banner-content">
                <AlertTriangle className="banner-icon-danger" size={24} />
                <div>
                  <strong>Audit Chain Corruption / Tamper Detected!</strong>
                  <p>
                    {chainResult.detail || chainResult.error || `Broken at event #${chainResult.broken_at_id}`}
                  </p>
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* Sub Tabs */}
      <div className="sub-tabs-bar">
        <button
          type="button"
          className={`sub-tab ${activeSubTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('audit')}
        >
          Audit Trail Explorer ({auditTotal})
        </button>
        <button
          type="button"
          className={`sub-tab ${activeSubTab === 'alerts' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('alerts')}
        >
          Security Alerts ({alerts.length})
        </button>
        <button
          type="button"
          className={`sub-tab ${activeSubTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('users')}
        >
          User Management
        </button>
        <button
          type="button"
          className={`sub-tab ${activeSubTab === 'activity' ? 'active' : ''}`}
          onClick={() => {
            setActiveSubTab('activity');
            loadUserActivity(0);
            loadLoginHistory();
          }}
        >
          Administrative Activity
        </button>
      </div>


      {/* Tab 1: Audit Trail */}
      {activeSubTab === 'audit' && (
        <div className="card">
          {/* Filters Bar */}
          <div className="audit-filters-grid">
            <input
              type="text"
              placeholder="Action (e.g. doc_upload, suggest_confirm)"
              value={auditAction}
              onChange={(e) => setAuditAction(e.target.value)}
            />
            <select value={auditOutcome} onChange={(e) => setAuditOutcome(e.target.value)}>
              <option value="">All Outcomes</option>
              <option value="allowed">Allowed</option>
              <option value="denied">Denied</option>
            </select>
            <input
              type="text"
              placeholder="Actor UUID"
              value={auditActor}
              onChange={(e) => setAuditActor(e.target.value)}
            />
            <input
              type="text"
              placeholder="Document UUID"
              value={auditDoc}
              onChange={(e) => setAuditDoc(e.target.value)}
            />
            <div className="audit-actions-cell">
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => loadAudit(0)}
                disabled={loadingAudit}
              >
                <Filter size={14} /> Filter
              </button>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={handleExportCsv}
                title="Download CSV"
              >
                <Download size={14} /> Export CSV
              </button>
            </div>
          </div>

          {/* Audit Events Table */}
          {loadingAudit ? (
            <div className="loading-state">
              <div className="spinner"></div>
              <p>Fetching immutable audit trail...</p>
            </div>
          ) : auditEvents.length === 0 ? (
            <div className="empty-state">
              <p>No audit events match your filters.</p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="table table-sm">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Outcome</th>
                    <th>Actor ID</th>
                    <th>Doc ID</th>
                    <th>IP</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((e) => {
                    const isExpanded = expandedRow === e.id;
                    return (
                      <React.Fragment key={e.id}>
                        <tr className="audit-row" onClick={() => setExpandedRow(isExpanded ? null : e.id)}>
                          <td><code>#{e.id}</code></td>
                          <td className="text-xs">{e.ts ? new Date(e.ts).toLocaleString() : 'N/A'}</td>
                          <td>
                            <span className="badge-action">{e.action}</span>
                          </td>
                          <td>
                            {e.outcome === 'allowed' ? (
                              <span className="badge-pill badge-allowed">Allowed</span>
                            ) : (
                              <span className="badge-pill badge-denied">Denied</span>
                            )}
                          </td>
                          <td className="text-xs font-mono">
                            {e.actor_id ? `${e.actor_id.slice(0, 8)}...` : 'system'}
                          </td>
                          <td className="text-xs font-mono">
                            {e.doc_id ? `${e.doc_id.slice(0, 8)}...` : '-'}
                          </td>
                          <td className="text-xs">{e.ip || '-'}</td>
                          <td>
                            <button type="button" className="btn-icon">
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </button>
                          </td>
                        </tr>
                        {isExpanded && (
                          <tr className="audit-detail-row">
                            <td colSpan={8}>
                              <div className="audit-detail-payload">
                                <div className="hash-meta-row">
                                  <span>Hash: <code>{e.hash}</code></span>
                                  <span>Prev Hash: <code>{e.prev_hash || 'genesis'}</code></span>
                                </div>
                                <pre>{JSON.stringify(e.detail, null, 2)}</pre>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          <div className="pagination-bar">
            <span>
              Showing {auditEvents.length} of {auditTotal} events
            </span>
            <div className="page-btns">
              <button
                type="button"
                className="btn btn-outline btn-xs"
                disabled={auditOffset === 0 || loadingAudit}
                onClick={() => loadAudit(Math.max(0, auditOffset - 25))}
              >
                Previous
              </button>
              <button
                type="button"
                className="btn btn-outline btn-xs"
                disabled={auditOffset + 25 >= auditTotal || loadingAudit}
                onClick={() => loadAudit(auditOffset + 25)}
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Security Alerts */}
      {activeSubTab === 'alerts' && (
        <div className="alerts-container">
          {alerts.length === 0 ? (
            <div className="card empty-state">
              <CheckCircle className="text-success" size={40} />
              <h3>All Quiet</h3>
              <p>No anomalous patterns detected (denial spikes, odd-hours downloads, bulk downloads).</p>
            </div>
          ) : (
            <div className="alerts-grid">
              {alerts.map((al, idx) => (
                <div key={idx} className="card alert-card">
                  <div className="alert-card-header">
                    <ShieldAlert className="text-danger" size={20} />
                    <span className="alert-type">{al.type || 'Security Warning'}</span>
                  </div>
                  <p className="alert-desc">{al.message || al.description || JSON.stringify(al)}</p>
                  {al.timestamp && (
                    <span className="text-xs text-muted">
                      Triggered: {new Date(al.timestamp).toLocaleString()}
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: User Management */}
      {activeSubTab === 'users' && (
        <div className="user-mgmt-grid">
          {/* Create User Form */}
          <div className="card">
            <h3 className="card-title">
              <UserPlus size={18} /> Register New Vault User
            </h3>

            {regSuccess && (
              <div className="alert alert-success">
                <Check size={16} /> <span>{regSuccess}</span>
              </div>
            )}
            {regErr && (
              <div className="alert alert-error">
                <X size={16} /> <span>{regErr}</span>
              </div>
            )}

            <form onSubmit={handleRegisterUser} className="form-group">
              <div className="input-group">
                <label>User Email</label>
                <input
                  type="email"
                  required
                  placeholder="collaborator@trustvault.local"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                />
              </div>
              <div className="input-group">
                <label>Full Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Jane Doe"
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                />
              </div>
              <div className="input-group">
                <label>Initial Password (min 8 chars)</label>
                <input
                  type="password"
                  required
                  placeholder="StrongPassphrase123!"
                  value={regPw}
                  onChange={(e) => setRegPw(e.target.value)}
                />
              </div>
              <div className="input-group">
                <label>Role</label>
                <select value={regRole} onChange={(e) => setRegRole(e.target.value)}>
                  <option value="viewer">viewer (content consumer)</option>
                  <option value="owner">owner (can upload & manage documents)</option>
                  <option value="admin">admin (audit & user manager only)</option>
                </select>
              </div>
              <button type="submit" className="btn btn-primary" disabled={creatingUser}>
                {creatingUser ? 'Registering...' : 'Create User'}
              </button>
            </form>
          </div>

          {/* Quick User Revocation Controls */}
          <div className="card">
            <h3 className="card-title">
              <Lock size={18} /> Instant Session & Access Revocation
            </h3>
            <p className="text-muted text-sm" style={{ marginBottom: '1rem' }}>
              Enforces immediate session termination on the next request.
            </p>

            {userActionMsg && (
              <div className="alert alert-success">
                <Check size={16} /> <span>{userActionMsg}</span>
              </div>
            )}
            {userActionErr && (
              <div className="alert alert-error">
                <X size={16} /> <span>{userActionErr}</span>
              </div>
            )}

            <div className="form-group">
              <div className="input-group">
                <label>Target User UUID</label>
                <input
                  type="text"
                  placeholder="00000000-0000-0000-0000-000000000000"
                  value={actionUserId}
                  onChange={(e) => setActionUserId(e.target.value)}
                />
              </div>
              <div className="btn-row">
                <button
                  type="button"
                  className="btn btn-outline btn-sm"
                  onClick={handleBumpVersion}
                >
                  <RotateCw size={14} /> Invalidate Tokens (Bump Version)
                </button>
                <button
                  type="button"
                  className="btn btn-danger btn-sm"
                  onClick={handleDisableUser}
                >
                  <Ban size={14} /> Disable User (Kill Access)
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Administrative Activity */}
      {activeSubTab === 'activity' && (
        <div className="admin-activity-container">

          {/* View Mode Toggle */}
          <div className="activity-mode-toggle">
            <button
              type="button"
              className={`btn btn-sm ${activityViewMode === 'all' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActivityViewMode('all')}
            >
              All Activity
            </button>
            <button
              type="button"
              className={`btn btn-sm ${activityViewMode === 'logins' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActivityViewMode('logins')}
            >
              Login History
            </button>
          </div>

          {/* LOGIN HISTORY VIEW */}
          {activityViewMode === 'logins' && (
            <div className="card">
              <h3 className="card-title">
                <ShieldAlert size={18} /> Login History (last 30 days)
              </h3>
              {loginLoading ? (
                <div className="loading-state"><div className="spinner" /><p>Loading logins...</p></div>
              ) : loginEvents.length === 0 ? (
                <div className="empty-state"><p>No login events found.</p></div>
              ) : (
                <div className="table-responsive">
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Email</th>
                        <th>Outcome</th>
                        <th>IP Address</th>
                      </tr>
                    </thead>
                    <tbody>
                      {loginEvents.map((ev) => (
                        <tr key={ev.id}>
                          <td className="text-xs">{ev.ts ? new Date(ev.ts).toLocaleString() : '—'}</td>
                          <td><strong>{ev.actor_name || 'Unknown'}</strong></td>
                          <td>
                            <span className={`role-badge role-${ev.actor_role || 'unknown'}`}>
                              {ev.actor_role || '—'}
                            </span>
                          </td>
                          <td className="text-xs">{ev.actor_email || '—'}</td>
                          <td>
                            {ev.outcome === 'allowed'
                              ? <span className="badge-pill badge-allowed">Success</span>
                              : <span className="badge-pill badge-denied">Failed</span>}
                          </td>
                          <td className="text-xs font-mono">{ev.ip || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* ALL ACTIVITY VIEW */}
          {activityViewMode === 'all' && (
            <div className="card">
              <h3 className="card-title">
                <Search size={18} /> All User Actions (last 30 days)
              </h3>

              {/* Filters */}
              <div className="audit-filters-grid" style={{ marginBottom: '1rem' }}>
                <select
                  value={activityActionFilter}
                  onChange={(e) => setActivityActionFilter(e.target.value)}
                >
                  <option value="">All Actions</option>
                  <option value="auth_login">auth_login</option>
                  <option value="auth_logout">auth_logout</option>
                  <option value="doc_upload">doc_upload</option>
                  <option value="doc_download">doc_download</option>
                  <option value="doc_view">doc_view</option>
                  <option value="grant_create">grant_create</option>
                  <option value="grant_revoke">grant_revoke</option>
                  <option value="suggest_access">suggest_access</option>
                  <option value="confirm_suggestions">confirm_suggestions</option>
                  <option value="audit_verify">audit_verify</option>
                  <option value="admin_activity_view">admin_activity_view</option>
                </select>
                <input
                  type="text"
                  placeholder="Actor UUID (optional)"
                  value={activityActorFilter}
                  onChange={(e) => setActivityActorFilter(e.target.value)}
                />
                <input
                  type="date"
                  value={activitySinceFilter}
                  onChange={(e) => setActivitySinceFilter(e.target.value)}
                  title="Show events from this date"
                />
                <div className="audit-actions-cell">
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    onClick={() => loadUserActivity(0)}
                    disabled={activityLoading}
                  >
                    <Filter size={14} /> Apply
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline btn-sm"
                    onClick={() => {
                      setActivityActionFilter('');
                      setActivityActorFilter('');
                      setActivitySinceFilter('');
                      setTimeout(() => loadUserActivity(0), 0);
                    }}
                  >
                    Clear
                  </button>
                </div>
              </div>

              {activityLoading ? (
                <div className="loading-state"><div className="spinner" /><p>Loading activity...</p></div>
              ) : activityEvents.length === 0 ? (
                <div className="empty-state"><p>No activity events found for the selected filters.</p></div>
              ) : (
                <>
                  <div className="table-responsive">
                    <table className="table table-sm">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>User</th>
                          <th>Role</th>
                          <th>Action</th>
                          <th>Outcome</th>
                          <th>Document ID</th>
                          <th>IP</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activityEvents.map((ev) => (
                          <tr key={ev.id} className="audit-row">
                            <td className="text-xs">{ev.ts ? new Date(ev.ts).toLocaleString() : '—'}</td>
                            <td>
                              <div><strong>{ev.actor_name || 'System'}</strong></div>
                              <div className="text-xs text-muted">{ev.actor_email || ''}</div>
                            </td>
                            <td>
                              <span className={`role-badge role-${ev.actor_role || 'unknown'}`}>
                                {ev.actor_role || '—'}
                              </span>
                            </td>
                            <td>
                              <span className={`badge-action action-${(ev.action || '').split('_')[0]}`}>
                                {ev.action}
                              </span>
                            </td>
                            <td>
                              {ev.outcome === 'allowed'
                                ? <span className="badge-pill badge-allowed">Allowed</span>
                                : <span className="badge-pill badge-denied">Denied</span>}
                            </td>
                            <td className="text-xs font-mono">
                              {ev.doc_id ? `${ev.doc_id.slice(0, 8)}…` : '—'}
                            </td>
                            <td className="text-xs">{ev.ip || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination */}
                  <div className="pagination-bar">
                    <span>Showing {activityEvents.length} of {activityTotal} events</span>
                    <div className="page-btns">
                      <button
                        type="button"
                        className="btn btn-outline btn-xs"
                        disabled={activityOffset === 0 || activityLoading}
                        onClick={() => loadUserActivity(Math.max(0, activityOffset - 50))}
                      >
                        Previous
                      </button>
                      <button
                        type="button"
                        className="btn btn-outline btn-xs"
                        disabled={activityOffset + 50 >= activityTotal || activityLoading}
                        onClick={() => loadUserActivity(activityOffset + 50)}
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
