import React, { useState } from 'react';
import { docApi } from '../api';
import { Upload, X, AlertCircle, FileCheck, Info } from 'lucide-react';

const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB
const ALLOWED_EXTS = ['pdf', 'docx', 'xlsx', 'png', 'jpg', 'jpeg', 'txt', 'csv'];
const CATEGORY_OPTIONS = ['General', 'Finance', 'Legal', 'Engineering', 'Marketing', 'HR', 'Tax'];

export default function UploadModal({ onClose, onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [name, setName] = useState('');
  const [category, setCategory] = useState('General');
  const [customCategory, setCustomCategory] = useState('');
  const [description, setDescription] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  function validateFile(selectedFile) {
    if (!selectedFile) return 'Please select a file to upload.';
    if (selectedFile.size > MAX_FILE_SIZE) {
      return `File exceeds maximum allowed size of 20MB (${(selectedFile.size / (1024 * 1024)).toFixed(1)}MB).`;
    }

    const rawName = selectedFile.name || '';
    const parts = rawName.split('.');
    if (parts.length < 2) {
      return 'File must have a valid extension.';
    }

    const ext = parts[parts.length - 1].toLowerCase();
    if (!ALLOWED_EXTS.includes(ext)) {
      return `File type '.${ext}' is not permitted. Allowed: ${ALLOWED_EXTS.join(', ')}`;
    }

    // Double extension check (e.g. doc.exe.pdf)
    if (parts.length > 2) {
      const secondExt = parts[parts.length - 2].toLowerCase();
      const dangerous = ['exe', 'sh', 'bat', 'cmd', 'js', 'vbs', 'py', 'msi', 'bin'];
      if (dangerous.includes(secondExt)) {
        return `Double extension with executable '${secondExt}' is forbidden.`;
      }
    }

    return null;
  }

  function handleFileChange(e) {
    const f = e.target.files[0];
    if (f) {
      const vError = validateFile(f);
      if (vError) {
        setErr(vError);
        setFile(null);
      } else {
        setErr('');
        setFile(f);
        if (!name) {
          setName(f.name.replace(/\.[^/.]+$/, ''));
        }
      }
    }
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setErr('');

    const vError = validateFile(file);
    if (vError) {
      setErr(vError);
      return;
    }

    setLoading(true);
    const finalCategory = category === 'Custom' ? customCategory.trim() || 'General' : category;

    const fd = new FormData();
    fd.append('file', file);
    if (name.trim()) fd.append('name', name.trim());
    fd.append('category', finalCategory);
    if (description.trim()) fd.append('description', description.trim());

    try {
      const doc = await docApi.upload(fd);
      onUploadSuccess(doc);
      onClose();
    } catch (e) {
      setErr(e.message || 'Upload failed. Please verify the file and metadata.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal-content">
        <div className="modal-header">
          <div className="modal-title-wrap">
            <Upload className="modal-icon" size={20} />
            <h3>Upload Encrypted Document</h3>
          </div>
          <button type="button" className="btn-close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {err && (
          <div className="alert alert-error">
            <AlertCircle size={18} />
            <span>{err}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="form-group">
          <div className="file-drop-area">
            <input
              type="file"
              id="file-input"
              className="file-input-hidden"
              onChange={handleFileChange}
              accept=".pdf,.docx,.xlsx,.png,.jpg,.jpeg,.txt,.csv"
            />
            <label htmlFor="file-input" className="file-drop-label">
              <Upload className="drop-icon" size={32} />
              {file ? (
                <div className="selected-file-info">
                  <FileCheck className="file-check-icon" size={20} />
                  <strong>{file.name}</strong>
                  <span className="file-size-tag">
                    ({(file.size / (1024 * 1024)).toFixed(2)} MB)
                  </span>
                </div>
              ) : (
                <div className="drop-prompt">
                  <strong>Click to select a file</strong> or drag and drop
                  <span className="drop-limits">
                    Allowed: PDF, DOCX, XLSX, PNG, JPG, TXT, CSV (Max 20MB)
                  </span>
                </div>
              )}
            </label>
          </div>

          <div className="input-group">
            <label htmlFor="doc-name">Document Title</label>
            <input
              id="doc-name"
              type="text"
              placeholder="e.g. Q4 Financial Audit Report"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="input-group">
            <label htmlFor="doc-category">Category</label>
            <div className="category-select-row">
              <select
                id="doc-category"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
              >
                {CATEGORY_OPTIONS.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
                <option value="Custom">+ Custom Category...</option>
              </select>
              {category === 'Custom' && (
                <input
                  type="text"
                  placeholder="Enter category name"
                  value={customCategory}
                  onChange={(e) => setCustomCategory(e.target.value)}
                  autoFocus
                />
              )}
            </div>
          </div>

          <div className="input-group">
            <label htmlFor="doc-desc">Description (Optional)</label>
            <textarea
              id="doc-desc"
              rows={3}
              placeholder="Brief summary of document purpose..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div className="info-banner">
            <Info size={16} />
            <span>
              All documents are encrypted with AES-256-GCM before writing to disk.
              File contents are never shared with AI or third parties.
            </span>
          </div>

          <div className="modal-actions">
            <button type="button" className="btn btn-outline" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading || !file}>
              {loading ? 'Encrypting & Uploading...' : 'Upload & Encrypt'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
