import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom';
import Dashboard     from './pages/Dashboard';
import Incidents     from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import Approvals     from './pages/Approvals';
import './App.css';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        {/* Sidebar nav */}
        <nav className="sidebar">
          <div className="sidebar-logo">
            <span className="logo-icon">🛡️</span>
            <span className="logo-text">AI-SOC</span>
          </div>
          <ul className="nav-list">
            <li>
              <NavLink to="/dashboard" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                📊 Dashboard
              </NavLink>
            </li>
            <li>
              <NavLink to="/incidents" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                📋 Incidents
              </NavLink>
            </li>
            <li>
              <NavLink to="/approvals" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
                ✅ Approvals
              </NavLink>
            </li>
          </ul>
        </nav>

        {/* Main content */}
        <main className="main-content">
          <Routes>
            <Route path="/"                        element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard"               element={<Dashboard />} />
            <Route path="/incidents"               element={<Incidents />} />
            <Route path="/incidents/:incidentId"   element={<IncidentDetail />} />
            <Route path="/approvals"               element={<Approvals />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
