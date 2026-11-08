import React, { useState, useEffect } from 'react';
import { docApi } from '../api';
import { Search, Filter, RotateCcw, Download, Eye, Trash2, FileText, Calendar, User, AlertCircle, Plus } from 'lucide-react';

export default function DocumentList({ currentUser, onSelectDoc, onOpenUpload }) {
  const [docs, setDocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');

  // Search filter states
  const [nameFilter, setNameFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [ownerFilter, setOwnerFilter] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [deletingId, setDeletingId] = useState(null);

  useEffect(() => {
    fetchDocuments();
  }, []);

  async function fetchDocuments(filters = null) {
    setLoading(true);
    setErr('');
    try {
      let data;
      if (filters && Object.values(filters).some((v) => v && v.trim())) {
        data = await docApi.search(filters);
      } else {
        data = await docApi.list();
      }
      setDocs(data || []);
    } catch (e) {
      setErr(e.message || 'Failed to retrieve documents.');
    } finally {
      setLoading(false);
    }
  }

  function handleSearchSubmit(e) {
    e.preventDefault();
    fetchDocuments({
      name: nameFilter,
      category: categoryFilter,
      owner: ownerFilter,
      from_date: fromDate,
      to_date: toDate,
    });
  }

  function handleResetFilters() {
    setNameFilter('');
    setCategoryFilter('');
    setOwnerFilter('');
    setFromDate('');
    setToDate('');
    fetchDocuments();
  }

  async function handleDelete(docId, docName) {
    if (!window.confirm(`Are you sure you want to delete "${docName}"? This will soft-delete the document.`)) {
      return;
    }
    setDeletingId(docId);
    try {
      await docApi.delete(docId);
      setDocs((prev) => prev.filter((d) => d.id !== docId));
    } catch (e) {
      alert(`Deletion failed: ${e.message}`);
    } finally {
      setDeletingId(null);
    }
  }

  async function handleDownload(docId, docName) {
    try {
      await docApi.download(docId, docName);
    } catch (e) {
      alert(`Download failed: ${e.message}`);
    }
  }

  const isOwnerOrAdmin = currentUser && (currentUser.role === 'owner' || currentUser.role === 'admin');

  return (
    <div className="doc-list-view">
      <div className="page-header">
        <div>
          <h2>Documents</h2>
          <p className="subtitle">Encrypted vaults accessible only via explicit ownership or provable grants.</p>
        </div>
        {isOwnerOrAdmin && (
          <button type="button" className="btn btn-primary" onClick={onOpenUpload}>
            <Plus size={18} />
            <span>Upload Document</span>
          </button>
        )}
      </div>

      {err && (
        <div className="alert alert-error">
          <AlertCircle size={18} />
          <span>{err}</span>
        </div>
      )}

      {/* Search & Filter Bar */}
      <form onSubmit={handleSearchSubmit} className="search-filter-card">
        <div className="search-grid">
          <div className="search-input-wrap">
            <Search className="search-icon" size={16} />
            <input
              type="text"
              placeholder="Search document name (ILIKE)..."
              value={nameFilter}
              onChange={(e) => setNameFilter(e.target.value)}
            />
          </div>

          <div className="filter-input-wrap">
            <input
              type="text"
              placeholder="Category (e.g. Finance, Legal)..."
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            />
          </div>

          <div className="filter-input-wrap">
            <input
              type="text"
              placeholder="Owner (email or name)..."
              value={ownerFilter}
              onChange={(e) => setOwnerFilter(e.target.value)}
            />
          </div>

          <div className="date-filter-wrap">
            <input
              type="date"
              title="From Created Date"
              value={fromDate}
              onChange={(e) => setFromDate(e.target.value)}
            />
            <span className="date-separator">to</span>
            <input
              type="date"
              title="To Created Date"
              value={toDate}
              onChange={(e) => setToDate(e.target.value)}
            />
          </div>
        </div>

        <div className="search-actions-row">
          <button type="submit" className="btn btn-primary btn-sm" disabled={loading}>
            <Filter size={14} />
            <span>Apply Search</span>
          </button>
          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={handleResetFilters}
            disabled={loading}
          >
            <RotateCcw size={14} />
            <span>Clear Filters</span>
          </button>
        </div>
      </form>

      {/* Document Table / Cards */}
      {loading ? (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Querying authorized documents...</p>
        </div>
      ) : docs.length === 0 ? (
        <div className="empty-state card">
          <FileText className="empty-icon" size={48} />
          <h3>No accessible documents found</h3>
          <p>
            Documents you do not have permission to view are strictly excluded by the database WHERE clause.
          </p>
          {isOwnerOrAdmin && (
            <button type="button" className="btn btn-primary btn-sm" onClick={onOpenUpload}>
              <Plus size={16} /> Upload your first document
            </button>
          )}
        </div>
      ) : (
        <div className="table-responsive card">
          <table className="table">
            <thead>
              <tr>
                <th>Document</th>
                <th>Category</th>
                <th>Created</th>
                <th>Access Type</th>
                <th>Versions</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {docs.map((d) => {
                const isDocOwner = currentUser && currentUser.id === d.owner_id;
                const vCount = d.versions ? d.versions.length : 1;
                return (
                  <tr key={d.id} className="doc-row">
                    <td>
                      <div className="doc-cell" onClick={() => onSelectDoc(d)} role="button" tabIndex={0}>
                        <FileText className="doc-type-icon" size={20} />
                        <div>
                          <strong className="doc-link-title">{d.name}</strong>
                          {d.description && <p className="doc-cell-desc">{d.description}</p>}
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className="badge-category">{d.category}</span>
                    </td>
                    <td>
                      <span className="text-muted text-sm">
                        {d.created_at ? new Date(d.created_at).toLocaleDateString() : 'N/A'}
                      </span>
                    </td>
                    <td>
                      {isDocOwner ? (
                        <span className="badge-pill badge-owner">Owner</span>
                      ) : (
                        <span className="badge-pill badge-viewer">Granted</span>
                      )}
                    </td>
                    <td>
                      <span className="badge-version">v{vCount}</span>
                    </td>
                    <td>
                      <div className="actions-cell">
                        <button
                          type="button"
                          className="btn-icon"
                          title="View Details, Versions & Sharing"
                          onClick={() => onSelectDoc(d)}
                        >
                          <Eye size={16} />
                        </button>
                        <button
                          type="button"
                          className="btn-icon"
                          title="Download Decrypted File"
                          onClick={() => handleDownload(d.id, d.name)}
                        >
                          <Download size={16} />
                        </button>
                        {isDocOwner && (
                          <button
                            type="button"
                            className="btn-icon btn-icon-danger"
                            title="Soft Delete Document"
                            onClick={() => handleDelete(d.id, d.name)}
                            disabled={deletingId === d.id}
                          >
                            <Trash2 size={16} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
