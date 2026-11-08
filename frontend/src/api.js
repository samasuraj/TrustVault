// TrustVault API client with cookie auth, CSRF headers, and clean error extraction

export function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)tv_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

export async function apiFetch(path, options = {}) {
  const opts = { ...options };
  opts.credentials = 'include';
  opts.headers = { ...(opts.headers || {}) };

  const method = (opts.method || 'GET').toUpperCase();
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const csrf = getCsrfToken();
    if (csrf) {
      opts.headers['X-CSRF-Token'] = csrf;
    }
  }

  // If body is JSON string and content-type not set, set it
  if (opts.body && typeof opts.body === 'string' && !opts.headers['Content-Type']) {
    opts.headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(path, opts);

  // Handle binary/download responses
  if (options.responseType === 'blob') {
    if (!res.ok) {
      const err = await parseError(res);
      throw new Error(err);
    }
    return res.blob();
  }

  let data = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const message = extractErrorMessage(res.status, data);
    const error = new Error(message);
    error.status = res.status;
    error.data = data;
    throw error;
  }

  return data;
}

function extractErrorMessage(status, data) {
  if (status === 401) {
    return 'Authentication required or session expired. Please log in.';
  }
  if (status === 404) {
    if (data?.detail && typeof data.detail === 'string') return data.detail;
    return 'Document not found or access denied.';
  }
  if (status === 422) {
    if (Array.isArray(data?.detail)) {
      return data.detail.map(d => `${d.loc?.slice(1).join('.') || 'input'}: ${d.msg}`).join('; ');
    }
    if (typeof data?.detail === 'string') return data.detail;
    return 'Invalid input submission.';
  }
  if (status === 413) {
    return 'File size exceeds 20MB limit.';
  }
  if (status === 403) {
    return data?.detail || 'Permission denied or CSRF token mismatch.';
  }
  if (data?.detail && typeof data.detail === 'string') {
    return data.detail;
  }
  return `Request failed with status ${status}`;
}

async function parseError(res) {
  try {
    const json = await res.json();
    return extractErrorMessage(res.status, json);
  } catch {
    return extractErrorMessage(res.status, null);
  }
}

// -------------------------------------------------------------
// Auth API
// -------------------------------------------------------------
export const authApi = {
  getMe: () => apiFetch('/api/auth/me'),
  login: async (email, password) => {
    const data = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    return data?.user || data;
  },
  logout: () =>
    apiFetch('/api/auth/logout', {
      method: 'POST',
    }),
  registerUser: (payload) =>
    apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  disableUser: (userId) =>
    apiFetch(`/api/auth/users/${userId}/disable`, {
      method: 'POST',
    }),
  bumpTokenVersion: (userId) =>
    apiFetch(`/api/auth/users/${userId}/bump-version`, {
      method: 'POST',
    }),
};

// -------------------------------------------------------------
// Documents API
// -------------------------------------------------------------
export const docApi = {
  list: () => apiFetch('/api/documents'),
  search: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.name?.trim()) params.append('name', filters.name.trim());
    if (filters.category?.trim()) params.append('category', filters.category.trim());
    if (filters.owner?.trim()) params.append('owner', filters.owner.trim());
    if (filters.from_date) params.append('from_date', filters.from_date);
    if (filters.to_date) params.append('to_date', filters.to_date);
    const qs = params.toString();
    return apiFetch(`/api/search${qs ? `?${qs}` : ''}`);
  },
  get: (docId) => apiFetch(`/api/documents/${docId}`),
  upload: (formData) =>
    apiFetch('/api/documents', {
      method: 'POST',
      body: formData,
    }),
  update: (docId, formData) =>
    apiFetch(`/api/documents/${docId}`, {
      method: 'PUT',
      body: formData,
    }),
  delete: (docId) =>
    apiFetch(`/api/documents/${docId}`, {
      method: 'DELETE',
    }),
  download: async (docId, filename = 'document.bin') => {
    const blob = await apiFetch(`/api/documents/${docId}/download`, {
      responseType: 'blob',
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },
};

// -------------------------------------------------------------
// Sharing & AI Suggestions API
// -------------------------------------------------------------
export const shareApi = {
  listGrants: (docId) => apiFetch(`/api/documents/${docId}/grants`),
  createGrant: (docId, { user_email, perm, expires_at }) =>
    apiFetch(`/api/documents/${docId}/grants`, {
      method: 'POST',
      body: JSON.stringify({ user_email, perm, expires_at: expires_at || null }),
    }),
  revokeGrant: (docId, grantId) =>
    apiFetch(`/api/documents/${docId}/grants/${grantId}`, {
      method: 'DELETE',
    }),
  suggestAccess: (docId) =>
    apiFetch(`/api/documents/${docId}/suggest-access`, {
      method: 'POST',
    }),
  confirmSuggestions: (docId, sid, { decision, grants }) =>
    apiFetch(`/api/documents/${docId}/suggestions/${sid}/confirm`, {
      method: 'POST',
      body: JSON.stringify({ decision, grants }),
    }),
};

// -------------------------------------------------------------
// Admin API
// -------------------------------------------------------------
export const adminApi = {
  getAuditEvents: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.action) params.append('action', filters.action);
    if (filters.outcome) params.append('outcome', filters.outcome);
    if (filters.actor_id) params.append('actor_id', filters.actor_id);
    if (filters.doc_id) params.append('doc_id', filters.doc_id);
    if (filters.from_date) params.append('from_date', filters.from_date);
    if (filters.to_date) params.append('to_date', filters.to_date);
    params.append('limit', filters.limit || 50);
    params.append('offset', filters.offset || 0);
    return apiFetch(`/api/admin/audit?${params.toString()}`);
  },
  verifyChain: () => apiFetch('/api/admin/audit/verify'),
  getActivity: () => apiFetch('/api/admin/activity'),
  getAlerts: () => apiFetch('/api/admin/activity/alerts'),
  getUserActivity: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.action) params.append('action', filters.action);
    if (filters.actor_id) params.append('actor_id', filters.actor_id);
    if (filters.since) params.append('since', filters.since);
    params.append('limit', filters.limit || 100);
    params.append('offset', filters.offset || 0);
    return apiFetch(`/api/admin/user-activity?${params.toString()}`);
  },
  exportAuditCsv: async (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.action) params.append('action', filters.action);
    if (filters.outcome) params.append('outcome', filters.outcome);
    params.append('export', 'csv');
    const blob = await apiFetch(`/api/admin/audit?${params.toString()}`, {
      responseType: 'blob',
    });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trustvault-audit-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  },
};
