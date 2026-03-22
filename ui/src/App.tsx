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
import Rollups from './pages/Rollups';
import Settings from './pages/Settings';
import { AnalysisProvider } from './context/AnalysisContext';
import './index.css';

function App() {
  return (
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
            <Route path="/rollups" element={<Rollups />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </AnalysisProvider>
  );
}

export default App;
