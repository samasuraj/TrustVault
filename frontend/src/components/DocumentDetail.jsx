import React, { useState, useEffect } from 'react';
import { docApi, shareApi } from '../api';
import {
  ArrowLeft, Download, Trash2, Clock, Share2, Sparkles, AlertCircle, CheckCircle2,
  XCircle, FileText, UserPlus, UserMinus, Shield, UploadCloud
} from 'lucide-react';

export default function DocumentDetail({ docId, currentUser, onBack }) {
  const [doc, setDoc] = useState(null);
  const [grants, setGrants] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // New version state
  const [newVersionFile, setNewVersionFile] = useState(null);
  const [uploadingVersion, setUploadingVersion] = useState(false);

  // New grant form state
  const [grantEmail, setGrantEmail] = useState('');
  const [grantPerm, setGrantPerm] = useState('read');
  const [grantExpiry, setGrantExpiry] = useState('');
  const [granting, setGranting] = useState(false);

  // AI Suggestions state
  const [suggestions, setSuggestions] = useState([]);
  const [suggestionSid, setSuggestionSid] = useState(null);
  const [loadingSuggestions, setLoadingSuggestions] = useState(false);
  const [selectedSuggestions, setSelectedSuggestions] = useState({}); // { email: { selected: bool, perm: 'read'|'edit' } }
  const [decisionOutcome, setDecisionOutcome] = useState('');

  useEffect(() => {
    loadDocumentDetails();
  }, [docId]);

  async function loadDocumentDetails() {
    setLoading(true);
    setErr('');
    try {
      const d = await docApi.get(docId);
      setDoc(d);

      // If current user is owner, load grants
      if (currentUser && currentUser.id === d.owner_id) {
        try {
          const g = await shareApi.listGrants(docId);
          setGrants(g || []);
        } catch {
          setGrants([]);
        }
      }
    } catch (e) {
      setErr(e.message || 'Failed to load document details.');
    } finally {
      setLoading(false);
    }
  }

  async function handleDownload() {
    if (!doc) return;
    try {
      await docApi.download(doc.id, doc.name);
    } catch (e) {
      alert(`Download failed: ${e.message}`);
    }
  }

  async function handleUploadNewVersion(e) {
    e.preventDefault();
    if (!newVersionFile) return;
    setUploadingVersion(true);
    setErr('');
    try {
      const fd = new FormData();
      fd.append('file', newVersionFile);
      const updated = await docApi.update(doc.id, fd);
      setDoc(updated);
      setNewVersionFile(null);
      setSuccessMsg('New version uploaded and encrypted successfully.');
      setTimeout(() => setSuccessMsg(''), 4000);
    } catch (e) {
      setErr(`Version upload failed: ${e.message}`);
    } finally {
      setUploadingVersion(false);
    }
  }

  async function handleCreateGrant(e) {
    e.preventDefault();
    if (!grantEmail.trim()) return;
    setGranting(true);
    setErr('');
    try {
      await shareApi.createGrant(doc.id, {
        user_email: grantEmail.trim(),
        perm: grantPerm,
        expires_at: grantExpiry ? new Date(grantExpiry).toISOString() : null,
      });
      setGrantEmail('');
      setGrantExpiry('');
      setSuccessMsg(`Access granted to ${grantEmail}`);
      setTimeout(() => setSuccessMsg(''), 4000);
      const g = await shareApi.listGrants(doc.id);
      setGrants(g || []);
    } catch (e) {
      setErr(`Grant creation failed: ${e.message}`);
    } finally {
      setGranting(false);
    }
  }

  async function handleRevokeGrant(grantId, email) {
    if (!window.confirm(`Revoke document access for ${email || 'this user'}? Access dies immediately on their next request.`)) {
      return;
    }
    try {
      await shareApi.revokeGrant(doc.id, grantId);
      setGrants((prev) => prev.filter((g) => g.id !== grantId));
      setSuccessMsg(`Access revoked immediately for ${email || 'user'}`);
      setTimeout(() => setSuccessMsg(''), 4000);
    } catch (e) {
      alert(`Revocation failed: ${e.message}`);
    }
  }

  // --- AI Suggestions Handlers ---
  async function handleGetSuggestions() {
    setLoadingSuggestions(true);
    setErr('');
    setDecisionOutcome('');
    try {
      const res = await shareApi.suggestAccess(doc.id);
      setSuggestionSid(res.sid || res.suggestion_id);
      const list = res.suggestions || [];
      setSuggestions(list);

      // Initialize selected map (default all checked with suggested permission)
      const sel = {};
      list.forEach((s) => {
        sel[s.email] = {
          selected: true,
          perm: s.suggested_perm || s.perm || 'read',
          userId: s.user_id,
        };
      });
      setSelectedSuggestions(sel);
    } catch (e) {
      setErr(`Failed to generate AI recommendations: ${e.message}`);
    } finally {
      setLoadingSuggestions(false);
    }
  }

  function handleToggleSuggestion(email) {
    setSelectedSuggestions((prev) => ({
      ...prev,
      [email]: {
        ...prev[email],
        selected: !prev[email]?.selected,
      },
    }));
  }

  function handlePermChange(email, newPerm) {
    setSelectedSuggestions((prev) => ({
      ...prev,
      [email]: {
        ...prev[email],
        perm: newPerm,
      },
    }));
  }

  async function handleConfirmSuggestions(decisionType) {
    if (!suggestionSid) return;
    setLoadingSuggestions(true);
    setErr('');
    try {
      let picks = [];
      if (decisionType !== 'rejected') {
        Object.entries(selectedSuggestions).forEach(([email, item]) => {
          if (item.selected) {
            picks.push({
              user_email: email,
              user_id: item.userId,
              perm: item.perm || 'read',
            });
          }
        });
      }

      const res = await shareApi.confirmSuggestions(doc.id, suggestionSid, {
        decision: decisionType === 'rejected' ? 'rejected' : undefined,
        grants: picks,
      });

      setDecisionOutcome(res.decision || 'confirmed');
      setSuggestions([]);
      setSuggestionSid(null);
      setSuccessMsg(`Suggestions ${res.decision || 'confirmed'}! Granted access to ${picks.length} user(s).`);
      setTimeout(() => setSuccessMsg(''), 5000);

      // Refresh grants list
      const updatedGrants = await shareApi.listGrants(doc.id);
      setGrants(updatedGrants || []);
    } catch (e) {
      setErr(`Failed to confirm suggestions: ${e.message}`);
    } finally {
      setLoadingSuggestions(false);
    }
  }

  if (loading) {
    return (
      <div className="loading-state">
        <div className="spinner"></div>
        <p>Verifying document access and decrypting metadata...</p>
      </div>
    );
  }

  if (err && !doc) {
    return (
      <div className="card">
        <div className="alert alert-error">
          <AlertCircle size={20} />
          <div>
            <strong>Access Denied or Document Not Found</strong>
            <p>{err}</p>
          </div>
        </div>
        <button type="button" className="btn btn-outline" onClick={onBack}>
          <ArrowLeft size={16} /> Return to Documents
        </button>
      </div>
    );
  }

  const isOwner = currentUser && doc && currentUser.id === doc.owner_id;

  return (
    <div className="doc-detail-view">
      {/* Top Navigation */}
      <div className="detail-top-nav">
        <button type="button" className="btn btn-outline btn-sm" onClick={onBack}>
          <ArrowLeft size={16} />
          <span>Back to Documents</span>
        </button>
      </div>

      {successMsg && (
        <div className="alert alert-success">
          <CheckCircle2 size={18} />
          <span>{successMsg}</span>
        </div>
      )}

      {err && (
        <div className="alert alert-error">
          <AlertCircle size={18} />
          <span>{err}</span>
        </div>
      )}

      {/* Document Header Card */}
      <div className="card doc-header-card">
        <div className="doc-header-main">
          <div className="doc-title-row">
            <FileText className="doc-icon-large" />
            <div>
              <h2>{doc.name}</h2>
              <div className="doc-meta-tags">
                <span className="badge-category">{doc.category}</span>
                {isOwner ? (
                  <span className="badge-pill badge-owner">You are Owner</span>
                ) : (
                  <span className="badge-pill badge-viewer">Active Grant</span>
                )}
                <span className="text-muted text-sm">
                  Created {doc.created_at ? new Date(doc.created_at).toLocaleString() : 'N/A'}
                </span>
              </div>
            </div>
          </div>

          <div className="doc-header-actions">
            <button type="button" className="btn btn-primary" onClick={handleDownload}>
              <Download size={16} />
              <span>Download File</span>
            </button>
          </div>
        </div>

        {doc.description && (
          <div className="doc-description-box">
            <p>{doc.description}</p>
          </div>
        )}
      </div>

      <div className="detail-grid">
        {/* Left Column: Versions */}
        <div className="card">
          <div className="card-header-row">
            <h3 className="card-title">
              <Clock size={18} /> Version History
            </h3>
            <span className="text-muted text-xs">
              {isOwner ? 'Full History (Owner View)' : 'Current Version Only'}
            </span>
          </div>

          <div className="version-list">
            {(doc.versions || []).map((v) => (
              <div key={v.id} className="version-item">
                <div className="version-badge-wrap">
                  <span className="badge-version">v{v.version_no}</span>
                  <span className="version-date">
                    {v.created_at ? new Date(v.created_at).toLocaleDateString() : 'Active'}
                  </span>
                </div>
                <div className="version-specs">
                  <span>{(v.size / 1024).toFixed(1)} KB</span>
                  <span className="bullet">•</span>
                  <span className="mime-tag">{v.mime}</span>
                </div>
                <div className="sha-preview" title={v.sha256}>
                  SHA-256: <code>{v.sha256 ? `${v.sha256.slice(0, 12)}...` : 'N/A'}</code>
                </div>
              </div>
            ))}
          </div>

          {/* Upload New Version */}
          <form onSubmit={handleUploadNewVersion} className="version-upload-form">
            <label className="text-sm font-semibold">Upload New Version</label>
            <div className="file-input-inline">
              <input
                type="file"
                id="new-version-file"
                className="file-input-hidden"
                onChange={(e) => setNewVersionFile(e.target.files[0])}
                accept=".pdf,.docx,.xlsx,.png,.jpg,.jpeg,.txt,.csv"
              />
              <label htmlFor="new-version-file" className="btn btn-outline btn-sm">
                <UploadCloud size={14} />
                <span>{newVersionFile ? newVersionFile.name : 'Choose File...'}</span>
              </label>
              <button
                type="submit"
                className="btn btn-primary btn-sm"
                disabled={!newVersionFile || uploadingVersion}
              >
                {uploadingVersion ? 'Uploading...' : 'Upload v' + ((doc.versions?.length || 1) + 1)}
              </button>
            </div>
          </form>
        </div>

        {/* Right Column: Sharing & AI Assistant (Owner Only) */}
        {isOwner ? (
          <div className="sharing-column">
            {/* AI Sharing Assistant Panel */}
            <div className="card ai-card">
              <div className="card-header-row">
                <div className="ai-title-wrap">
                  <Sparkles className="ai-icon" size={18} />
                  <h3>AI Sharing Assistant</h3>
                </div>
                <button
                  type="button"
                  className="btn btn-ai btn-sm"
                  onClick={handleGetSuggestions}
                  disabled={loadingSuggestions}
                >
                  {loadingSuggestions ? 'Analyzing Heuristics...' : 'Get Recommendations'}
                </button>
              </div>

              <p className="ai-desc">
                Suggests team members based on category history and owner collaboration.
                Suggestions <strong>never create grants</strong> until explicitly confirmed.
              </p>

              {decisionOutcome && (
                <div className={`alert ${decisionOutcome === 'rejected' ? 'alert-warning' : 'alert-success'}`}>
                  <CheckCircle2 size={16} />
                  <span>Decision recorded: <strong>{decisionOutcome}</strong></span>
                </div>
              )}

              {suggestions.length > 0 && (
                <div className="suggestions-list">
                  <div className="suggestions-header">
                    <span>Suggested Users</span>
                    <span>Permission</span>
                  </div>
                  {suggestions.map((s) => {
                    const selState = selectedSuggestions[s.email] || { selected: true, perm: 'read' };
                    return (
                      <div key={s.email} className={`suggestion-row ${selState.selected ? 'selected' : ''}`}>
                        <div className="suggestion-check-col">
                          <input
                            type="checkbox"
                            checked={selState.selected}
                            onChange={() => handleToggleSuggestion(s.email)}
                            id={`chk-${s.email}`}
                          />
                          <label htmlFor={`chk-${s.email}`} className="suggestion-label">
                            <span className="suggestion-name">{s.name || s.email}</span>
                            <span className="suggestion-email">{s.email}</span>
                            <span className="suggestion-reason">{s.reason}</span>
                          </label>
                        </div>

                        <div className="suggestion-perm-col">
                          <select
                            value={selState.perm}
                            onChange={(e) => handlePermChange(s.email, e.target.value)}
                            disabled={!selState.selected}
                            className="perm-select"
                          >
                            <option value="read">read</option>
                            <option value="edit">edit</option>
                          </select>
                        </div>
                      </div>
                    );
                  })}

                  <div className="suggestions-actions-row">
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={() => handleConfirmSuggestions('accepted')}
                      disabled={loadingSuggestions}
                    >
                      <CheckCircle2 size={14} /> Accept & Grant Selected
                    </button>
                    <button
                      type="button"
                      className="btn btn-outline btn-sm text-danger"
                      onClick={() => handleConfirmSuggestions('rejected')}
                      disabled={loadingSuggestions}
                    >
                      <XCircle size={14} /> Reject All
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Active Grants & Grant Form */}
            <div className="card">
              <div className="card-header-row">
                <h3 className="card-title">
                  <Share2 size={18} /> Access Grants
                </h3>
                <span className="badge-pill badge-neutral">{grants.length} Active</span>
              </div>

              {/* Create Grant Form */}
              <form onSubmit={handleCreateGrant} className="add-grant-form">
                <div className="grant-inputs-grid">
                  <input
                    type="email"
                    required
                    placeholder="Recipient email address"
                    value={grantEmail}
                    onChange={(e) => setGrantEmail(e.target.value)}
                  />
                  <select value={grantPerm} onChange={(e) => setGrantPerm(e.target.value)}>
                    <option value="read">read</option>
                    <option value="edit">edit</option>
                  </select>
                  <input
                    type="datetime-local"
                    title="Optional Expiry Date"
                    value={grantExpiry}
                    onChange={(e) => setGrantExpiry(e.target.value)}
                  />
                  <button type="submit" className="btn btn-primary btn-sm" disabled={granting}>
                    <UserPlus size={14} />
                    <span>{granting ? 'Granting...' : 'Grant'}</span>
                  </button>
                </div>
              </form>

              {/* Grants Table */}
              {grants.length === 0 ? (
                <p className="text-muted text-sm" style={{ marginTop: '1rem' }}>
                  No active grants for this document. Use the form above or AI assistant to grant access.
                </p>
              ) : (
                <div className="table-responsive" style={{ marginTop: '1rem' }}>
                  <table className="table table-sm">
                    <thead>
                      <tr>
                        <th>User Email</th>
                        <th>Permission</th>
                        <th>Granted At</th>
                        <th>Expires</th>
                        <th className="text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {grants.map((g) => (
                        <tr key={g.id}>
                          <td><strong>{g.user_email || 'User'}</strong></td>
                          <td>
                            <span className={`badge-pill badge-${g.perm}`}>{g.perm}</span>
                          </td>
                          <td className="text-xs text-muted">
                            {g.granted_at ? new Date(g.granted_at).toLocaleDateString() : 'N/A'}
                          </td>
                          <td className="text-xs text-muted">
                            {g.expires_at ? new Date(g.expires_at).toLocaleString() : 'Permanent'}
                          </td>
                          <td className="text-right">
                            <button
                              type="button"
                              className="btn btn-danger btn-xs"
                              onClick={() => handleRevokeGrant(g.id, g.user_email)}
                              title="Instant Revocation"
                            >
                              <UserMinus size={12} />
                              <span>Revoke</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="card">
            <h3 className="card-title">
              <Shield size={18} /> Access Status
            </h3>
            <p className="text-muted text-sm">
              You have authorized access to view and download this document.
              Only the document owner may manage sharing grants and access recommendations.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
