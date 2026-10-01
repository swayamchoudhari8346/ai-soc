import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { fetchIncident, fetchActions, fetchAuditTrail, investigateIncident, executeActions } from '../api';

const SEVERITY_CLASS = {
  CRITICAL: 'sev-critical',
  HIGH:     'sev-high',
  MEDIUM:   'sev-medium',
  LOW:      'sev-low',
};

const STATUS_CLASS = {
  pending:  'status-pending',
  executed: 'status-executed',
  approved: 'status-approved',
  rejected: 'status-rejected',
  blocked:  'status-blocked',
};

const ACTOR_CLASS = {
  system:   'actor-system',
  ai_agent: 'actor-ai',
  analyst:  'actor-analyst',
  analyst1: 'actor-analyst',
};

function eventStyle(eventType) {
  if (eventType.startsWith('incident.'))    return { label: 'INCIDENT', cls: 'evt-incident' };
  if (eventType.startsWith('safety.'))      return { label: 'SAFETY',   cls: 'evt-safety'   };
  if (eventType.startsWith('approval.'))    return { label: 'APPROVAL', cls: 'evt-approval' };
  if (eventType.startsWith('action.'))      return { label: 'ACTION',   cls: 'evt-action'   };
  if (eventType.startsWith('remediation.')) return { label: 'DONE',     cls: 'evt-done'     };
  return { label: 'EVENT', cls: 'evt-other' };
}

/**
 * IncidentDetail page — shows a single incident with its AI report, actions,
 * and a full audit timeline.
 */
export default function IncidentDetail() {
  const { incidentId }          = useParams();
  const [incident, setIncident] = useState(null);
  const [actions, setActions]   = useState([]);
  const [auditLog, setAuditLog] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [working, setWorking]   = useState(false);
  const [workMsg, setWorkMsg]   = useState('');

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [inc, acts, audit] = await Promise.all([
        fetchIncident(incidentId),
        fetchActions(incidentId),
        fetchAuditTrail(incidentId),
      ]);
      setIncident(inc);
      setActions(acts);
      setAuditLog(audit);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadData(); }, [incidentId]);

  async function handleInvestigate() {
    setWorking(true);
    setWorkMsg('Running AI investigation…');
    try {
      await investigateIncident(incidentId);
      setWorkMsg('Investigation done. Running safety engine…');
      await executeActions(incidentId);
      setWorkMsg('Done.');
      await loadData();
    } catch (err) {
      setWorkMsg(`Error: ${err.message}`);
    } finally {
      setWorking(false);
    }
  }

  if (loading) return <div className="page"><p className="status-msg">Loading…</p></div>;
  if (error)   return <div className="page"><p className="status-msg error">Error: {error}</p></div>;
  if (!incident) return null;

  const report = incident.ai_report ?? {};

  return (
    <div className="page">
      <div className="page-header">
        <div>
          <Link to="/incidents" className="back-link">← Incidents</Link>
          <h1>{incident.incident_id}</h1>
        </div>
        <button
          className="btn btn-primary"
          onClick={handleInvestigate}
          disabled={working}
        >
          {working ? workMsg : '⚡ Investigate + Queue Actions'}
        </button>
      </div>

      {/* Incident summary */}
      <section className="card">
        <h2>Incident</h2>
        <dl className="kv-grid">
          <dt>Severity</dt>
          <dd><span className={`sev-badge ${SEVERITY_CLASS[incident.severity] ?? ''}`}>{incident.severity}</span></dd>
          <dt>Status</dt>
          <dd>{incident.status}</dd>
          <dt>Asset</dt>
          <dd>{incident.affected_asset ?? '—'}</dd>
          <dt>Created</dt>
          <dd>{new Date(incident.created_at).toLocaleString()}</dd>
          <dt>Classification</dt>
          <dd>{incident.classification ?? '—'}</dd>
          <dt>Confidence</dt>
          <dd>{incident.confidence != null ? `${(incident.confidence * 100).toFixed(0)}%` : '—'}</dd>
        </dl>
      </section>

      {/* AI Report */}
      {Object.keys(report).length > 0 && (
        <section className="card">
          <h2>AI Investigation Report</h2>
          <dl className="kv-grid">
            <dt>MITRE Technique</dt>
            <dd>{report.mitre_technique ?? '—'}{report.mitre_technique_name ? ` — ${report.mitre_technique_name}` : ''}</dd>
            <dt>Summary</dt>
            <dd>{report.summary ?? '—'}</dd>
            <dt>Evidence</dt>
            <dd>{report.evidence_summary ?? '—'}</dd>
            <dt>RAG Sources</dt>
            <dd>{(report.rag_context ?? []).join(', ') || '—'}</dd>
            <dt>Prompt Injection</dt>
            <dd>{report.prompt_injection_detected ? '⚠️ Detected' : 'None detected'}</dd>
          </dl>
        </section>
      )}

      {/* Actions table */}
      <section className="card">
        <h2>Actions ({actions.length})</h2>
        {actions.length === 0 ? (
          <p className="status-msg">No actions yet — click Investigate to generate them.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Target</th>
                <th>Risk</th>
                <th>Policy</th>
                <th>Status</th>
                <th>Policy Reason</th>
              </tr>
            </thead>
            <tbody>
              {actions.map(action => (
                <tr key={action.id}>
                  <td><code>{action.action_type}</code></td>
                  <td><code>{action.target}</code></td>
                  <td>
                    <span className={`risk-badge risk-${action.risk_level}`}>
                      L{action.risk_level}
                    </span>
                  </td>
                  <td>{action.policy_decision}</td>
                  <td>
                    <span className={`status-badge ${STATUS_CLASS[action.status] ?? ''}`}>
                      {action.status}
                    </span>
                  </td>
                  <td className="policy-reason">{action.policy_reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* Audit timeline */}
      <section className="card timeline-card">
        <h2>Audit Timeline ({auditLog.length} events)</h2>
        {auditLog.length === 0 ? (
          <p className="status-msg">No audit events yet.</p>
        ) : (
          <ol className="timeline">
            {auditLog.map(entry => {
              const { label, cls } = eventStyle(entry.event_type);
              const ts    = (entry.timestamp ?? '').slice(0, 19).replace('T', ' ');
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
      </section>
    </div>
  );
}
