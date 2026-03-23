import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import FileUpload from './pages/FileUpload';
import Incidents from './pages/Incidents';
import IncidentDetail from './pages/IncidentDetail';
import Analysis from './pages/Analysis';
import PipelineView from './pages/PipelineView';
import MitreMapping from './pages/MitreMapping';
import Validation from './pages/Validation';
import Settings from './pages/Settings';
import LogEvents from './pages/LogEvents';
import { AnalysisProvider } from './context/AnalysisContext';
import { ThemeProvider } from './context/ThemeContext';
import './index.css';

function App() {
  return (
    <ThemeProvider>
      <AnalysisProvider>
        <BrowserRouter>
          <Layout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/upload" element={<FileUpload />} />
              <Route path="/pipeline" element={<PipelineView />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/incidents/:id" element={<IncidentDetail />} />
              <Route path="/analysis" element={<Analysis />} />
              <Route path="/mitre" element={<MitreMapping />} />
              <Route path="/validation" element={<Validation />} />
              <Route path="/log-events" element={<LogEvents />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </Layout>
        </BrowserRouter>
      </AnalysisProvider>
    </ThemeProvider>
  );
}

export default App;
