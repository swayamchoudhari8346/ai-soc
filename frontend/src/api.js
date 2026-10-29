/**
 * api.js — Centralised API client for the AI-SOC backend.
 *
 * All requests go through the Vite dev proxy: /api → http://localhost:8000
 * In production, set VITE_API_BASE to the backend URL.
 */

export const API_BASE = import.meta.env.VITE_API_BASE ?? '/api';

/**
 * Thin fetch wrapper — throws an Error with the response body on non-2xx.
 */
async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail ?? JSON.stringify(body);
    } catch {
      // ignore parse error
    }
    throw new Error(detail);
  }

  // 204 No Content
  if (res.status === 204) return null;
  return res.json();
}

// ── Incidents ─────────────────────────────────────────────────────────────────

/** List incidents, newest first. Backend pagination uses `skip`, not `offset`. */
export function fetchIncidents(limit = 50, skip = 0) {
  return request(`/incidents/?limit=${limit}&skip=${skip}`);
}

/** Get a single incident by incident_id. */
export function fetchIncident(incidentId) {
  return request(`/incidents/${incidentId}`);
}

/** List all actions for an incident. */
export function fetchActions(incidentId) {
  return request(`/incidents/${incidentId}/actions`);
}

/** Trigger AI investigation for an incident. */
export function investigateIncident(incidentId) {
  return request(`/incidents/${incidentId}/investigate`, { method: 'POST' });
}

/** Run pending actions through the safety engine. */
export function executeActions(incidentId) {
  return request(`/incidents/${incidentId}/execute-actions`, { method: 'POST' });
}

/** Get dashboard summary stats. */
export function fetchStats() {
  return request('/incidents/stats');
}

/** Get the full audit trail for an incident. */
export function fetchAuditTrail(incidentId) {
  return request(`/incidents/${incidentId}/audit`);
}

// ── Approvals ─────────────────────────────────────────────────────────────────

/**
 * Fetch approvals filtered by status.
 * @param {'pending'|'approved'|'rejected'|'all'} status
 */
export function fetchApprovals(status = 'pending') {
  return request(`/approvals?status=${status}`);
}

/** Get a single approval by id. */
export function fetchApproval(approvalId) {
  return request(`/approvals/${approvalId}`);
}

/**
 * Submit an analyst decision on a queued action.
 * @param {number} approvalId
 * @param {'approved'|'rejected'} decision
 * @param {string} approver
 * @param {string} reason
 */
export function decideApproval(approvalId, decision, approver = 'analyst', reason = '') {
  return request(`/approvals/${approvalId}/decide`, {
    method: 'POST',
    body: JSON.stringify({ decision, approver, reason }),
  });
}

/**
 * Execute analyst-approved actions for an incident (simulated remediation).
 * Call after a successful approve decision so action/audit states advance.
 */
export function executeApproved(incidentId) {
  return request(`/incidents/${incidentId}/execute-approved`, { method: 'POST' });
}
