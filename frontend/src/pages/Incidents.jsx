import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchIncidents } from '../api';

const SEVERITY_CLASS = {
  CRITICAL: 'sev-critical',
  HIGH:     'sev-high',
  MEDIUM:   'sev-medium',
  LOW:      'sev-low',
};

/**
 * Incidents page — lists all incidents, newest first.
 */
export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);

  async function loadIncidents() {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchIncidents(50);
      setIncidents(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadIncidents(); }, []);

  return (
    <div className="page">
      <div className="page-header">
        <h1>Incidents</h1>
        <button className="btn btn-secondary" onClick={loadIncidents}>
          ↻ Refresh
        </button>
      </div>

      {loading && <p className="status-msg">Loading incidents…</p>}
      {error   && <p className="status-msg error">Error: {error}</p>}

      {!loading && !error && incidents.length === 0 && (
        <div className="empty-state">
          <span className="empty-icon">📭</span>
          <p>No incidents found.</p>
        </div>
      )}

      {!loading && incidents.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Incident ID</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Classification</th>
              <th>Asset</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map(inc => (
              <tr key={inc.incident_id}>
                <td>
                  <Link to={`/incidents/${inc.incident_id}`} className="incident-link">
                    {inc.incident_id}
                  </Link>
                </td>
                <td>
                  <span className={`sev-badge ${SEVERITY_CLASS[inc.severity] ?? ''}`}>
                    {inc.severity}
                  </span>
                </td>
                <td>{inc.status}</td>
                <td>{inc.classification ?? '—'}</td>
                <td>{inc.affected_asset ?? '—'}</td>
                <td>{new Date(inc.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
