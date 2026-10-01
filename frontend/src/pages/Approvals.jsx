import { useEffect, useState } from 'react';
import { fetchApprovals, decideApproval } from '../api';

/**
 * Approvals page — shows the pending approval queue.
 * Analyst can approve or reject each queued action.
 */
export default function Approvals() {
  const [approvals, setApprovals] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  // Track per-row loading state: { [approvalId]: true }
  const [deciding, setDeciding]   = useState({});

  async function loadApprovals() {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchApprovals('pending');
      setApprovals(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadApprovals(); }, []);

  async function handleDecide(approvalId, decision) {
    setDeciding(prev => ({ ...prev, [approvalId]: true }));
    try {
      await decideApproval(approvalId, decision, 'analyst', '');
      // Remove decided row from list
      setApprovals(prev => prev.filter(a => a.id !== approvalId));
    } catch (err) {
      alert(`Decision failed: ${err.message}`);
    } finally {
      setDeciding(prev => ({ ...prev, [approvalId]: false }));
    }
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1>Approval Queue</h1>
        <button className="btn btn-secondary" onClick={loadApprovals}>
          ↻ Refresh
        </button>
      </div>

      {loading && <p className="status-msg">Loading approvals…</p>}
      {error   && <p className="status-msg error">Error: {error}</p>}

      {!loading && !error && approvals.length === 0 && (
        <div className="empty-state">
          <span className="empty-icon">✅</span>
          <p>No pending approvals — all clear.</p>
        </div>
      )}

      {!loading && approvals.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Incident</th>
              <th>Action</th>
              <th>Target</th>
              <th>Risk</th>
              <th>Policy Reason</th>
              <th>Decision</th>
            </tr>
          </thead>
          <tbody>
            {approvals.map(approval => {
              const action   = approval.action ?? {};
              const busy     = !!deciding[approval.id];
              const riskLevel = action.risk_level ?? '?';

              return (
                <tr key={approval.id}>
                  <td>{approval.id}</td>
                  <td>
                    <a href={`/incidents/${action.incident_id}`} className="incident-link">
                      {action.incident_id ?? '—'}
                    </a>
                  </td>
                  <td><code>{action.action_type ?? '—'}</code></td>
                  <td><code>{action.target ?? '—'}</code></td>
                  <td>
                    <span className={`risk-badge risk-${riskLevel}`}>
                      L{riskLevel}
                    </span>
                  </td>
                  <td className="policy-reason">{action.policy_reason ?? '—'}</td>
                  <td className="action-btns">
                    <button
                      className="btn btn-approve"
                      onClick={() => handleDecide(approval.id, 'approved')}
                      disabled={busy}
                    >
                      {busy ? '…' : '✓ Approve'}
                    </button>
                    <button
                      className="btn btn-reject"
                      onClick={() => handleDecide(approval.id, 'rejected')}
                      disabled={busy}
                    >
                      {busy ? '…' : '✗ Reject'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
