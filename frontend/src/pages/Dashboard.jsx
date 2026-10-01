import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { fetchStats, fetchIncidents, fetchAuditTrail } from '../api';

const SEVERITY_CLASS = {
  CRITICAL: 'sev-critical',
  HIGH:     'sev-high',
  MEDIUM:   'sev-medium',
  LOW:      'sev-low',
};

const ACTOR_CLASS = {
  system:    'actor-system',
  ai_agent:  'actor-ai',
  analyst:   'actor-analyst',
  analyst1:  'actor-analyst',
};

// Map event_type prefixes to a short label and colour class
function eventStyle(eventType) {
  if (eventType.startsWith('incident.'))  return { label: 'INCIDENT', cls: 'evt-incident' };
  if (eventType.startsWith('safety.'))    return { label: 'SAFETY',   cls: 'evt-safety'   };
  if (eventType.startsWith('approval.'))  return { label: 'APPROVAL', cls: 'evt-approval' };
  if (eventType.startsWith('action.'))    return { label: 'ACTION',   cls: 'evt-action'   };
  if (eventType.startsWith('remediation.')) return { label: 'DONE',   cls: 'evt-done'     };
  return { label: 'EVENT', cls: 'evt-other' };
}

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, accent }) {
  return (
    <div className="stat-card" style={accent ? { borderTopColor: accent } : {}}>
      <div className="stat-value">{value ?? '—'}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

// ── Audit timeline ────────────────────────────────────────────────────────────
function AuditTimeline({ incidentId }) {
  const [entries, setEntries]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);

  useEffect(() => {
    if (!incidentId) return;
    setLoading(true);
    setError(null);
    fetchAuditTrail(incidentId)
      .then(setEntries)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [incidentId]);

  if (!incidentId) return null;

  return (
    <div className="card timeline-card">
      <h2>Audit Timeline — {incidentId}</h2>
      {loading && <p className="status-msg">Loading timeline…</p>}
      {error   && <p className="status-msg error">Error: {error}</p>}
      {!loading && !error && entries.length === 0 && (
        <p className="status-msg">No audit entries for this incident yet.</p>
      )}
      {!loading && entries.length > 0 && (
        <ol className="timeline">
          {entries.map(entry => {
            const { label, cls } = eventStyle(entry.event_type);
            const ts = (entry.timestamp ?? '').slice(0, 19).replace('T', ' ');
            const actor = entry.actor ?? 'system';
            return (
              <li key={entry.id} className="timeline-item">
                <div className="timeline-dot" />
                <div className="timeline-body">
                  <div className="timeline-header">
                    <span className={`evt-badge ${cls}`}>{label}</span>
                    <code className="evt-type">{entry.event_type}</code>
                    <span className={`actor-badge ${ACTOR_CLASS[actor] ?? 'actor-system'}`}>
                      {actor}
                    </span>
                    <span className="timeline-ts">{ts}</span>
                  </div>
                  <p className="timeline-desc">{entry.description}</p>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

// ── Dashboard page ────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [stats, setStats]               = useState(null);
  const [incidents, setIncidents]       = useState([]);
  const [statsErr, setStatsErr]         = useState(null);
  const [incErr, setIncErr]             = useState(null);
  const [selectedId, setSelectedId]     = useState(null);

  async function loadAll() {
    setStatsErr(null);
    setIncErr(null);
    try { setStats(await fetchStats()); }
    catch (e) { setStatsErr(e.message); }
    try { setIncidents(await fetchIncidents(10)); }
    catch (e) { setIncErr(e.message); }
  }

  useEffect(() => { loadAll(); }, []);

  const sev = stats?.by_severity ?? {};

  return (
    <div className="page">
      <div className="page-header">
        <h1>Dashboard</h1>
        <button className="btn btn-secondary" onClick={loadAll}>↻ Refresh</button>
      </div>

      {/* ── Stat cards ──────────────────────────────────────────────────── */}
      {statsErr && <p className="status-msg error">Stats error: {statsErr}</p>}
      <div className="stat-grid">
        <StatCard label="Total Incidents"    value={stats?.total}                    accent="#388bfd" />
        <StatCard label="Open"               value={stats?.open}                     accent="#e3b341" />
        <StatCard label="Investigating"      value={stats?.investigating}             accent="#bc8cff" />
        <StatCard label="Pending Approvals"  value={stats?.pending_approvals_count}  accent="#ffa657" />
        <StatCard label="Resolved"           value={stats?.resolved}                 accent="#3fb950" />
        <StatCard label="Critical"           value={sev.CRITICAL ?? 0}               accent="#ff7b7b" />
        <StatCard label="High"               value={sev.HIGH ?? 0}                   accent="#ffa657" />
        <StatCard label="Medium"             value={sev.MEDIUM ?? 0}                 accent="#e3b341" />
        <StatCard label="Low"                value={sev.LOW ?? 0}                    accent="#56d364" />
      </div>

      {/* ── Recent incidents table ───────────────────────────────────────── */}
      <section className="card">
        <h2>Recent Incidents (last 10)</h2>
        {incErr && <p className="status-msg error">Error: {incErr}</p>}
        {!incErr && incidents.length === 0 && (
          <p className="status-msg">No incidents found.</p>
        )}
        {incidents.length > 0 && (
          <table className="data-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Classification</th>
                <th>Asset</th>
                <th>Created</th>
                <th>Timeline</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map(inc => (
                <tr
                  key={inc.incident_id}
                  className={selectedId === inc.incident_id ? 'row-selected' : ''}
                >
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
                  <td>
                    <button
                      className={`btn btn-secondary btn-xs ${selectedId === inc.incident_id ? 'btn-active' : ''}`}
                      onClick={() =>
                        setSelectedId(prev =>
                          prev === inc.incident_id ? null : inc.incident_id
                        )
                      }
                    >
                      {selectedId === inc.incident_id ? '▲ Hide' : '▼ Show'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* ── Audit timeline (renders below table when an incident is selected) */}
      <AuditTimeline incidentId={selectedId} />
    </div>
  );
}
