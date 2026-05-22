import { BrowserRouter, Navigate, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import FileUpload from './pages/FileUpload';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import PipelineView from './pages/PipelineView';
import MitreMapping from './pages/MitreMapping';
import Validation from './pages/Validation';
import Settings from './pages/Settings';
import LogEvents from './pages/LogEvents';
import { AnalysisProvider } from './context/AnalysisContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import Login from './pages/Login';
import './index.css';

function AppShell() {
  const { isAuthenticated, isInitializing } = useAuth();

  if (isInitializing) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100 px-4">
        <p className="text-sm font-medium text-slate-600">Checking authentication...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/upload" element={<FileUpload />} />
          <Route path="/log-flow" element={<PipelineView />} />
          <Route path="/pipeline" element={<Navigate to="/log-flow" replace />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/analysis" element={<LogEvents />} />
          <Route path="/mitre" element={<MitreMapping />} />
          <Route path="/validation" element={<Validation />} />
          <Route path="/log-events" element={<Navigate to="/analysis" replace />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AnalysisProvider>
          <AppShell />
        </AnalysisProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
