import axios from 'axios';

export const API_BASE_URL = 'http://localhost:8000/api/v1';

const api = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json',
    },
});

// File endpoints
export const uploadFile = async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await api.post('/files/upload', formData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    });
    return response.data;
};

export const getFiles = async () => {
    const response = await api.get('/files/');
    return response.data;
};

export const getFile = async (fileId: string) => {
    const response = await api.get(`/files/${fileId}`);
    return response.data;
};

// Analysis endpoints
export const analyzeFile = async (fileId: string) => {
    const response = await axios.post(`http://localhost:8000/api/v1/analyze?file_id=${fileId}`);
    return response.data;
};

export const getFileReportUrl = (fileId: string, download = true) => {
    const flag = download ? 'true' : 'false';
    return `${API_BASE_URL}/files/${fileId}/report?download=${flag}`;
};

export const getFileIncidentsJsonUrl = (fileId: string, download = true) => {
    const flag = download ? 'true' : 'false';
    return `${API_BASE_URL}/files/${fileId}/incidents-json?download=${flag}`;
};

export interface GeneratedReport {
    report_name: string;
    report_path: string;
    file_id: string | null;
    created_at: string;
    size_bytes: number;
}

export interface GeneratedReportContent extends GeneratedReport {
    content: string;
}

export const listGeneratedReports = async (fileId?: string): Promise<GeneratedReport[]> => {
    const params = new URLSearchParams();
    if (fileId) params.append('file_id', fileId);
    const query = params.toString();
    const route = `/files/reports${query ? `?${query}` : ''}`;
    try {
        const response = await api.get(route);
        return response.data;
    } catch (error: any) {
        if (error?.response?.status === 404) {
            const fallbackRoute = `/files/reports/${query ? `?${query}` : ''}`;
            const response = await api.get(fallbackRoute);
            return response.data;
        }
        throw error;
    }
};

export const getFileReportContent = async (fileId: string): Promise<GeneratedReportContent> => {
    const response = await api.get(`/files/${fileId}/report-content`);
    return response.data;
};

export const getFileIncidentsJsonContent = async (fileId: string): Promise<any> => {
    const response = await api.get(`/files/${fileId}/incidents-json?download=false`);
    return response.data;
};

// Incident endpoints
export const getIncidents = async (status?: string, priority?: string) => {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (priority) params.append('priority', priority);

    const response = await api.get(`/incidents/?${params.toString()}`);
    return response.data;
};

export const getIncident = async (incidentId: string) => {
    const response = await api.get(`/incidents/${incidentId}`);
    return response.data;
};

export const updateIncident = async (incidentId: string, update: any) => {
    const response = await api.patch(`/incidents/${incidentId}`, update);
    return response.data;
};

export const getIncidentReport = async (incidentId: string) => {
    const response = await api.get(`/incidents/${incidentId}/report`);
    return response.data;
};

export const getIncidentStats = async () => {
    const response = await api.get('/incidents/stats');
    return response.data;
};

// Health check
export const healthCheck = async () => {
    const response = await axios.get('http://localhost:8000/health');
    return response.data;
};

export default api;
