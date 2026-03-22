import { useEffect, useState } from 'react';
import {
    FileText,
    Database,
    Split,
    Brain,
    AlertTriangle,
    Search,
    Target,
    Zap,
    Eye,
    Cpu,
    Network,
    AlertCircle,
    CheckCircle,
    Clock,
    Hash,
    Users,
    Server,
    Activity,
    TrendingUp,
    Layers,
    MessageSquare
} from 'lucide-react';
import { getFiles, getIncidents } from '../api';

const API_BASE_URL = 'http://localhost:8000/api/v1';

interface FileData {
    file_id: string;
    filename?: string;
    original_filename?: string;
    status: string;
    size_bytes?: number;
    uploaded_at?: string;
    events_created?: number;
    parse_errors?: number;
    chunks_created?: number;
    suspicious_chunks_count?: number;
    ai_analysis_count?: number;
    incidents_created?: number;
}

interface IncidentData {
    incident_id: string;
    title: string;
    priority: string;
    primary_tactic?: string;
    severity?: string;
    file_id?: string;
    description?: string;
    mitre_techniques?: string[];
    chunk_count?: number;
}

interface AgentOutputs {
    has_data: boolean;
    total_chunks_analyzed?: number;
    avg_confidence?: number;
    behavioral?: {
        total: number;
        suspicious_count: number;
        sample_interpretations: string[];
        key_indicators: string[];
    };
    intent?: {
        total: number;
        suspected_intents: string[];
        kill_chain_stages: string[];
    };
    mitre?: {
        total: number;
        techniques: { id: string; name: string; tactic: string }[];
        tactics: string[];
    };
    triage?: {
        total: number;
        priorities: string[];
        executive_summaries: string[];
        recommended_actions: string[];
    };
}

export default function PipelineView() {
    const [files, setFiles] = useState<FileData[]>([]);
    const [incidents, setIncidents] = useState<IncidentData[]>([]);
    const [selectedFile, setSelectedFile] = useState<FileData | null>(null);
    const [agentOutputs, setAgentOutputs] = useState<AgentOutputs | null>(null);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [filesData, incidentsData] = await Promise.all([
                    getFiles().catch(() => []),
                    getIncidents().catch(() => [])
                ]);
                const processed = filesData.filter((f: FileData) => f.status === 'processed');
                setFiles(processed);
                setIncidents(incidentsData);
                if (processed.length > 0 && !selectedFile) {
                    setSelectedFile(processed[0]);
                }
            } catch (error) {
                console.error('Failed to fetch data:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 10000);
        return () => clearInterval(interval);
    }, [selectedFile]);

    // Fetch agent outputs when selected file changes
    useEffect(() => {
        const fetchAgentOutputs = async () => {
            if (!selectedFile) {
                setAgentOutputs(null);
                return;
            }
            try {
                const response = await fetch(`${API_BASE_URL}/agent-outputs/${selectedFile.file_id}`);
                if (response.ok) {
                    const data = await response.json();
                    setAgentOutputs(data);
                } else {
                    setAgentOutputs({ has_data: false });
                }
            } catch (error) {
                console.error('Failed to fetch agent outputs:', error);
                setAgentOutputs({ has_data: false });
            }
        };
        fetchAgentOutputs();
    }, [selectedFile]);


    const filteredFiles = files.filter(f => {
        const name = f.filename || f.original_filename || '';
        return name.toLowerCase().includes(searchTerm.toLowerCase());
    });

    const getFilename = (file: FileData) => file.filename || file.original_filename || 'Unknown';
    const getFileSize = (file: FileData) => file.size_bytes ? `${(file.size_bytes / 1024).toFixed(2)} KB` : 'Unknown';

    // Use incidents_created from file metadata (more reliable)
    const fileIncidentsCount = selectedFile?.incidents_created || 0;

    // Get all incidents to compute insights (since file_id might not be set on all)
    const allIncidents = incidents;

    // Compute insights from all incidents
    const threatInsights = {
        tactics: [...new Set(allIncidents.map(i => i.primary_tactic).filter(Boolean))],
        critical: allIncidents.filter(i => i.priority === 'critical').length,
        high: allIncidents.filter(i => i.priority === 'high').length,
        medium: allIncidents.filter(i => i.priority === 'medium').length,
        low: allIncidents.filter(i => i.priority === 'low').length,
    };

    // Stage-specific detailed info
    const eventsCreated = selectedFile?.events_created || 0;
    const parseErrors = selectedFile?.parse_errors || 0;
    const totalRows = eventsCreated + parseErrors;
    const successRate = totalRows > 0 ? ((eventsCreated / totalRows) * 100).toFixed(1) : '0';
    const chunksCreated = selectedFile?.chunks_created || 0;
    const suspiciousChunks = selectedFile?.suspicious_chunks_count || 0;
    const compressionRate = eventsCreated > 0 ? ((1 - (chunksCreated / eventsCreated)) * 100).toFixed(0) : '0';
    const aiAnalysesRun = selectedFile?.ai_analysis_count || 0;

    return (
        <div className="h-[calc(100vh-100px)] flex gap-6">
            {/* File List Sidebar */}
            <div className="w-80 flex-shrink-0 card flex flex-col">
                <div className="p-4 border-b border-white/10">
                    <h2 className="text-lg font-bold mb-3">Processed Files</h2>
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search files..."
                            className="input pl-10 text-sm"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                </div>
                <div className="flex-1 overflow-y-auto p-2 space-y-2">
                    {loading ? (
                        <div className="text-center p-4 text-gray-500 text-sm">Loading...</div>
                    ) : filteredFiles.length === 0 ? (
                        <div className="text-center p-4 text-gray-500 text-sm">No processed files</div>
                    ) : filteredFiles.map((file) => (
                        <button
                            key={file.file_id}
                            onClick={() => setSelectedFile(file)}
                            className={`w-full text-left p-3 rounded-lg transition-all border ${selectedFile?.file_id === file.file_id
                                ? 'bg-primary-500/20 border-primary-500/50'
                                : 'border-transparent hover:bg-white/5'
                                }`}
                        >
                            <p className="font-medium text-sm truncate">{getFilename(file)}</p>
                            <div className="flex justify-between mt-1.5 text-xs text-gray-400">
                                <span>{file.uploaded_at ? new Date(file.uploaded_at).toLocaleDateString() : ''}</span>
                                <span className={(file.incidents_created || 0) > 0 ? 'text-red-400' : 'text-green-400'}>
                                    {file.incidents_created || 0} incidents
                                </span>
                            </div>
                        </button>
                    ))}
                </div>
            </div>

            {/* Pipeline Visualization */}
            <div className="flex-1 overflow-hidden flex flex-col">
                {/* Header */}
                <div className="bg-surface-light rounded-xl p-5 mb-4 border border-white/10">
                    <div className="flex items-center justify-between">
                        <div>
                            <h1 className="text-2xl font-bold">Analysis Pipeline</h1>
                            <p className="text-gray-400 text-sm mt-1">
                                {selectedFile ? `Processing: ${getFilename(selectedFile)}` : 'Select a file to view pipeline'}
                            </p>
                        </div>
                        {selectedFile && (
                            <div className="flex gap-3">
                                <div className="text-center px-4 py-2 bg-surface-dark rounded-lg">
                                    <p className="text-xl font-bold text-blue-400">{eventsCreated}</p>
                                    <p className="text-xs text-gray-400">Events</p>
                                </div>
                                <div className="text-center px-4 py-2 bg-surface-dark rounded-lg">
                                    <p className="text-xl font-bold text-yellow-400">{chunksCreated}</p>
                                    <p className="text-xs text-gray-400">Chunks</p>
                                </div>
                                <div className="text-center px-4 py-2 bg-surface-dark rounded-lg">
                                    <p className="text-xl font-bold text-red-400">{fileIncidentsCount}</p>
                                    <p className="text-xs text-gray-400">Incidents</p>
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Pipeline Stages */}
                <div className="flex-1 overflow-y-auto space-y-4 pr-2">
                    {selectedFile ? (
                        <>
                            {/* Stage 1: Data Ingestion */}
                            <div className="bg-surface-light rounded-xl border border-blue-500/30 overflow-hidden">
                                <div className="bg-gradient-to-r from-blue-500/20 to-blue-600/10 px-5 py-3 flex items-center gap-3 border-b border-blue-500/20">
                                    <div className="w-10 h-10 rounded-lg bg-blue-500 flex items-center justify-center">
                                        <FileText className="w-5 h-5 text-white" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-base">Stage 1: Data Ingestion</h3>
                                        <p className="text-xs text-gray-400">File parsing and format detection</p>
                                    </div>
                                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Completed</span>
                                </div>
                                <div className="p-4 grid grid-cols-4 gap-3">
                                    <div className="bg-surface-dark rounded-lg p-3">
                                        <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                            <FileText className="w-3.5 h-3.5" /> File Name
                                        </div>
                                        <p className="font-medium text-sm truncate">{getFilename(selectedFile)}</p>
                                    </div>
                                    <div className="bg-surface-dark rounded-lg p-3">
                                        <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                            <Database className="w-3.5 h-3.5" /> File Size
                                        </div>
                                        <p className="font-medium text-sm">{getFileSize(selectedFile)}</p>
                                    </div>
                                    <div className="bg-surface-dark rounded-lg p-3">
                                        <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                            <Hash className="w-3.5 h-3.5" /> Total Rows
                                        </div>
                                        <p className="font-medium text-sm">{totalRows.toLocaleString()}</p>
                                    </div>
                                    <div className="bg-surface-dark rounded-lg p-3">
                                        <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                            <Cpu className="w-3.5 h-3.5" /> Parser Used
                                        </div>
                                        <p className="font-medium text-sm">Network Flow Parser</p>
                                    </div>
                                </div>
                            </div>

                            {/* Stage 2: Normalization */}
                            <div className="bg-surface-light rounded-xl border border-purple-500/30 overflow-hidden">
                                <div className="bg-gradient-to-r from-purple-500/20 to-purple-600/10 px-5 py-3 flex items-center gap-3 border-b border-purple-500/20">
                                    <div className="w-10 h-10 rounded-lg bg-purple-500 flex items-center justify-center">
                                        <Database className="w-5 h-5 text-white" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-base">Stage 2: Event Normalization</h3>
                                        <p className="text-xs text-gray-400">Standardize to common schema with enrichment</p>
                                    </div>
                                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Completed</span>
                                </div>
                                <div className="p-4">
                                    <div className="grid grid-cols-4 gap-3 mb-3">
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <CheckCircle className="w-3.5 h-3.5 text-green-400" /> Normalized
                                            </div>
                                            <p className="font-bold text-lg text-green-400">{eventsCreated.toLocaleString()}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <AlertCircle className="w-3.5 h-3.5 text-red-400" /> Parse Errors
                                            </div>
                                            <p className={`font-bold text-lg ${parseErrors > 0 ? 'text-red-400' : 'text-gray-400'}`}>{parseErrors}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <TrendingUp className="w-3.5 h-3.5" /> Success Rate
                                            </div>
                                            <p className="font-bold text-lg">{successRate}%</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Activity className="w-3.5 h-3.5 text-purple-400" /> Schema
                                            </div>
                                            <p className="font-medium text-sm text-purple-400">OCSF v1.0</p>
                                        </div>
                                    </div>
                                    <div className="bg-surface-dark rounded-lg p-3">
                                        <p className="text-xs text-gray-400 mb-2">Fields Extracted:</p>
                                        <div className="flex flex-wrap gap-1.5">
                                            {['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'action', 'bytes', 'user_agent'].map(field => (
                                                <span key={field} className="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded">{field}</span>
                                            ))}
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Stage 3: Behavioral Chunking */}
                            <div className="bg-surface-light rounded-xl border border-yellow-500/30 overflow-hidden">
                                <div className="bg-gradient-to-r from-yellow-500/20 to-orange-500/10 px-5 py-3 flex items-center gap-3 border-b border-yellow-500/20">
                                    <div className="w-10 h-10 rounded-lg bg-yellow-500 flex items-center justify-center">
                                        <Split className="w-5 h-5 text-white" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-base">Stage 3: Behavioral Chunking</h3>
                                        <p className="text-xs text-gray-400">Group events by actor, target, and time window</p>
                                    </div>
                                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Completed</span>
                                </div>
                                <div className="p-4">
                                    <div className="grid grid-cols-4 gap-3 mb-3">
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Layers className="w-3.5 h-3.5" /> Chunks Created
                                            </div>
                                            <p className="font-bold text-lg">{chunksCreated}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" /> Suspicious
                                            </div>
                                            <p className={`font-bold text-lg ${suspiciousChunks > 0 ? 'text-yellow-400' : 'text-gray-400'}`}>{suspiciousChunks}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Zap className="w-3.5 h-3.5 text-green-400" /> Compression
                                            </div>
                                            <p className="font-bold text-lg text-green-400">{compressionRate}%</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Clock className="w-3.5 h-3.5" /> Window
                                            </div>
                                            <p className="font-medium text-sm">5 minutes</p>
                                        </div>
                                    </div>
                                    <div className="bg-surface-dark rounded-lg p-3">
                                        <p className="text-xs text-gray-400 mb-2">Chunking Indexes:</p>
                                        <div className="grid grid-cols-3 gap-2">
                                            <div className="flex items-center gap-2 text-sm">
                                                <Users className="w-4 h-4 text-blue-400" />
                                                <span>By Source IP</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-sm">
                                                <Server className="w-4 h-4 text-green-400" />
                                                <span>By Destination</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-sm">
                                                <Network className="w-4 h-4 text-purple-400" />
                                                <span>By Protocol</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Stage 4: AI Agent Analysis - DETAILED */}
                            <div className="bg-surface-light rounded-xl border border-pink-500/30 overflow-hidden">
                                <div className="bg-gradient-to-r from-pink-500/20 to-purple-500/10 px-5 py-3 flex items-center gap-3 border-b border-pink-500/20">
                                    <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-pink-500 to-purple-500 flex items-center justify-center">
                                        <Brain className="w-5 h-5 text-white" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-base">Stage 4: AI Agent Analysis</h3>
                                        <p className="text-xs text-gray-400">Multi-agent threat intelligence with Llama 3.1</p>
                                    </div>
                                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Completed</span>
                                </div>
                                <div className="p-4">
                                    <div className="grid grid-cols-3 gap-3 mb-4">
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Cpu className="w-3.5 h-3.5" /> Chunks Analyzed
                                            </div>
                                            <p className="font-bold text-lg">{aiAnalysesRun || suspiciousChunks}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Brain className="w-3.5 h-3.5" /> Model
                                            </div>
                                            <p className="font-medium text-sm">Llama 3.1 (8B)</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
                                                <Zap className="w-3.5 h-3.5" /> Est. Tokens
                                            </div>
                                            <p className="font-medium text-sm">~{((aiAnalysesRun || suspiciousChunks) * 2000).toLocaleString()}</p>
                                        </div>
                                    </div>

                                    {/* AI Agents Detail */}
                                    <div className="space-y-3">
                                        <p className="text-sm font-medium text-gray-300 mb-2">Agent Pipeline: {agentOutputs?.has_data ? '(Actual Results)' : '(Generic Info)'}</p>

                                        {/* Behavioral Agent */}
                                        <div className="bg-surface-dark rounded-lg p-4 border-l-4 border-blue-500">
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-start gap-3">
                                                    <div className="w-8 h-8 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                                                        <Activity className="w-4 h-4 text-blue-400" />
                                                    </div>
                                                    <div className="flex-1">
                                                        <p className="font-medium text-sm">Behavioral Summary Agent</p>
                                                        {agentOutputs?.behavioral ? (
                                                            <div className="mt-2">
                                                                <div className="flex gap-3 text-xs mb-2">
                                                                    <span className="text-gray-400">Analyzed: <span className="text-white">{agentOutputs.behavioral.total}</span></span>
                                                                    <span className="text-yellow-400">Suspicious: {agentOutputs.behavioral.suspicious_count}</span>
                                                                </div>
                                                                {agentOutputs.behavioral.sample_interpretations.length > 0 && (
                                                                    <div className="bg-blue-500/10 rounded-lg p-3 mt-2">
                                                                        <p className="text-xs text-blue-300 font-medium mb-1">Sample Interpretation:</p>
                                                                        <p className="text-xs text-gray-300 leading-relaxed">{agentOutputs.behavioral.sample_interpretations[0]?.slice(0, 200)}...</p>
                                                                    </div>
                                                                )}
                                                                {agentOutputs.behavioral.key_indicators.length > 0 && (
                                                                    <div className="mt-2 flex flex-wrap gap-1">
                                                                        {agentOutputs.behavioral.key_indicators.slice(0, 5).map((ind, i) => (
                                                                            <span key={i} className="text-xs px-2 py-0.5 bg-blue-500/20 text-blue-300 rounded">{ind}</span>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ) : (
                                                            <p className="text-xs text-gray-400 mt-0.5">Generates structured summaries of behavioral patterns</p>
                                                        )}
                                                    </div>
                                                </div>
                                                <span className="text-xs px-2 py-1 bg-green-500/10 text-green-400 rounded">✓ Run</span>
                                            </div>
                                        </div>

                                        {/* Threat Intent Agent */}
                                        <div className="bg-surface-dark rounded-lg p-4 border-l-4 border-orange-500">
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-start gap-3">
                                                    <div className="w-8 h-8 rounded-lg bg-orange-500/20 flex items-center justify-center flex-shrink-0">
                                                        <Eye className="w-4 h-4 text-orange-400" />
                                                    </div>
                                                    <div className="flex-1">
                                                        <p className="font-medium text-sm">Threat Intent Agent</p>
                                                        {agentOutputs?.intent ? (
                                                            <div className="mt-2">
                                                                <div className="flex gap-3 text-xs mb-2">
                                                                    <span className="text-gray-400">Analyzed: <span className="text-white">{agentOutputs.intent.total}</span></span>
                                                                </div>
                                                                {agentOutputs.intent.suspected_intents.length > 0 && (
                                                                    <div className="bg-orange-500/10 rounded-lg p-3 mt-2">
                                                                        <p className="text-xs text-orange-300 font-medium mb-1">Suspected Intents:</p>
                                                                        <div className="flex flex-wrap gap-1">
                                                                            {agentOutputs.intent.suspected_intents.map((intent, i) => (
                                                                                <span key={i} className="text-xs px-2 py-1 bg-orange-500/20 text-orange-300 rounded">{intent}</span>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                )}
                                                                {agentOutputs.intent.kill_chain_stages.length > 0 && (
                                                                    <div className="mt-2 flex flex-wrap gap-1">
                                                                        <span className="text-xs text-gray-400 mr-1">Kill Chain:</span>
                                                                        {agentOutputs.intent.kill_chain_stages.map((stage, i) => (
                                                                            <span key={i} className="text-xs px-2 py-0.5 bg-red-500/20 text-red-300 rounded">{stage}</span>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ) : (
                                                            <p className="text-xs text-gray-400 mt-0.5">Infers attacker objectives and maps to kill chain stages</p>
                                                        )}
                                                    </div>
                                                </div>
                                                <span className="text-xs px-2 py-1 bg-green-500/10 text-green-400 rounded">✓ Run</span>
                                            </div>
                                        </div>

                                        {/* MITRE Mapping Agent */}
                                        <div className="bg-surface-dark rounded-lg p-4 border-l-4 border-purple-500">
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-start gap-3">
                                                    <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center flex-shrink-0">
                                                        <Target className="w-4 h-4 text-purple-400" />
                                                    </div>
                                                    <div className="flex-1">
                                                        <p className="font-medium text-sm">MITRE ATT&CK Mapping Agent</p>
                                                        {agentOutputs?.mitre ? (
                                                            <div className="mt-2">
                                                                <div className="flex gap-3 text-xs mb-2">
                                                                    <span className="text-gray-400">Techniques Mapped: <span className="text-white">{agentOutputs.mitre.total}</span></span>
                                                                </div>
                                                                {agentOutputs.mitre.techniques.length > 0 && (
                                                                    <div className="bg-purple-500/10 rounded-lg p-3 mt-2">
                                                                        <p className="text-xs text-purple-300 font-medium mb-2">Detected Techniques:</p>
                                                                        <div className="space-y-1">
                                                                            {agentOutputs.mitre.techniques.slice(0, 4).map((tech, i) => (
                                                                                <div key={i} className="flex items-center gap-2 text-xs">
                                                                                    <span className="px-1.5 py-0.5 bg-purple-500/30 text-purple-200 rounded font-mono">{tech.id}</span>
                                                                                    <span className="text-gray-300">{tech.name}</span>
                                                                                    <span className="text-gray-500">({tech.tactic})</span>
                                                                                </div>
                                                                            ))}
                                                                        </div>
                                                                    </div>
                                                                )}
                                                                {agentOutputs.mitre.tactics.length > 0 && (
                                                                    <div className="mt-2 flex flex-wrap gap-1">
                                                                        <span className="text-xs text-gray-400 mr-1">Tactics:</span>
                                                                        {agentOutputs.mitre.tactics.map((tactic, i) => (
                                                                            <span key={i} className="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded">{tactic}</span>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ) : (
                                                            <>
                                                                <p className="text-xs text-gray-400 mt-0.5">Maps behaviors to ATT&CK tactics, techniques, and sub-techniques</p>
                                                                {threatInsights.tactics.length > 0 && (
                                                                    <div className="mt-2 flex flex-wrap gap-1">
                                                                        {threatInsights.tactics.slice(0, 4).map((t, i) => (
                                                                            <span key={i} className="text-xs px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded">{t}</span>
                                                                        ))}
                                                                    </div>
                                                                )}
                                                            </>
                                                        )}
                                                    </div>
                                                </div>
                                                <span className="text-xs px-2 py-1 bg-green-500/10 text-green-400 rounded">✓ Run</span>
                                            </div>
                                        </div>

                                        {/* Triage Agent */}
                                        <div className="bg-surface-dark rounded-lg p-4 border-l-4 border-red-500">
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-start gap-3">
                                                    <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center flex-shrink-0">
                                                        <MessageSquare className="w-4 h-4 text-red-400" />
                                                    </div>
                                                    <div className="flex-1">
                                                        <p className="font-medium text-sm">Triage & Narrative Agent</p>
                                                        {agentOutputs?.triage ? (
                                                            <div className="mt-2">
                                                                <div className="flex gap-3 text-xs mb-2">
                                                                    <span className="text-gray-400">Triaged: <span className="text-white">{agentOutputs.triage.total}</span></span>
                                                                    {agentOutputs.triage.priorities.length > 0 && (
                                                                        <span className="text-red-400">Priorities: {agentOutputs.triage.priorities.join(', ')}</span>
                                                                    )}
                                                                </div>
                                                                {agentOutputs.triage.executive_summaries.length > 0 && (
                                                                    <div className="bg-red-500/10 rounded-lg p-3 mt-2">
                                                                        <p className="text-xs text-red-300 font-medium mb-1">Executive Summary:</p>
                                                                        <p className="text-xs text-gray-300 leading-relaxed">{agentOutputs.triage.executive_summaries[0]?.slice(0, 250)}...</p>
                                                                    </div>
                                                                )}
                                                                {agentOutputs.triage.recommended_actions.length > 0 && (
                                                                    <div className="mt-2">
                                                                        <p className="text-xs text-gray-400 mb-1">Recommended Actions:</p>
                                                                        <ul className="text-xs text-gray-300 list-disc list-inside space-y-0.5">
                                                                            {agentOutputs.triage.recommended_actions.slice(0, 3).map((action, i) => (
                                                                                <li key={i}>{action}</li>
                                                                            ))}
                                                                        </ul>
                                                                    </div>
                                                                )}
                                                            </div>
                                                        ) : (
                                                            <>
                                                                <p className="text-xs text-gray-400 mt-0.5">Assigns priority, generates executive & technical summaries</p>
                                                                <div className="mt-2 text-xs text-gray-500">
                                                                    <span className="text-red-400">Output:</span> Priority (Critical/High/Med/Low), risk assessment, recommended actions
                                                                </div>
                                                            </>
                                                        )}
                                                    </div>
                                                </div>
                                                <span className="text-xs px-2 py-1 bg-green-500/10 text-green-400 rounded">✓ Run</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            {/* Stage 5: Threat Detection */}
                            <div className="bg-surface-light rounded-xl border border-red-500/30 overflow-hidden">
                                <div className="bg-gradient-to-r from-red-500/20 to-red-600/10 px-5 py-3 flex items-center gap-3 border-b border-red-500/20">
                                    <div className="w-10 h-10 rounded-lg bg-red-500 flex items-center justify-center">
                                        <AlertTriangle className="w-5 h-5 text-white" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="font-bold text-base">Stage 5: Incident Correlation</h3>
                                        <p className="text-xs text-gray-400">Correlate agent outputs into incidents</p>
                                    </div>
                                    <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded-full">Completed</span>
                                </div>
                                <div className="p-4">
                                    <div className="grid grid-cols-5 gap-3 mb-3">
                                        <div className="bg-surface-dark rounded-lg p-3 text-center">
                                            <p className="text-xs text-gray-400 mb-1">Total</p>
                                            <p className="font-bold text-2xl">{fileIncidentsCount}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3 text-center border border-red-500/30">
                                            <p className="text-xs text-gray-400 mb-1">Critical</p>
                                            <p className="font-bold text-2xl text-red-400">{threatInsights.critical}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3 text-center border border-orange-500/30">
                                            <p className="text-xs text-gray-400 mb-1">High</p>
                                            <p className="font-bold text-2xl text-orange-400">{threatInsights.high}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3 text-center border border-yellow-500/30">
                                            <p className="text-xs text-gray-400 mb-1">Medium</p>
                                            <p className="font-bold text-2xl text-yellow-400">{threatInsights.medium}</p>
                                        </div>
                                        <div className="bg-surface-dark rounded-lg p-3 text-center border border-green-500/30">
                                            <p className="text-xs text-gray-400 mb-1">Low</p>
                                            <p className="font-bold text-2xl text-green-400">{threatInsights.low}</p>
                                        </div>
                                    </div>

                                    {/* Source File Info */}
                                    <div className="bg-surface-dark rounded-lg p-3 mb-3">
                                        <p className="text-xs text-gray-400 mb-2 font-medium">Source Traceability:</p>
                                        <div className="flex items-center gap-3 text-sm">
                                            <div className="flex items-center gap-2">
                                                <FileText className="w-4 h-4 text-blue-400" />
                                                <span className="text-gray-300">File:</span>
                                                <span className="font-mono text-xs bg-blue-500/10 px-2 py-0.5 rounded">{getFilename(selectedFile)}</span>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <Layers className="w-4 h-4 text-yellow-400" />
                                                <span className="text-gray-300">Chunks:</span>
                                                <span className="font-mono text-xs bg-yellow-500/10 px-2 py-0.5 rounded">{chunksCreated} total</span>
                                            </div>
                                        </div>
                                    </div>

                                    {/* MITRE Tactics */}
                                    {threatInsights.tactics.length > 0 && (
                                        <div className="bg-surface-dark rounded-lg p-3">
                                            <p className="text-xs text-gray-400 mb-2 font-medium">MITRE ATT&CK Coverage:</p>
                                            <div className="flex flex-wrap gap-1.5">
                                                {threatInsights.tactics.map((tactic, i) => (
                                                    <span key={i} className="text-xs px-2 py-1 bg-red-500/20 text-red-300 rounded-full flex items-center gap-1">
                                                        <Target className="w-3 h-3" /> {tactic}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </>
                    ) : (
                        <div className="h-full flex flex-col items-center justify-center text-gray-500">
                            <Split className="w-16 h-16 mb-4 opacity-20" />
                            <p className="text-lg">Select a file to view pipeline details</p>
                        </div>
                    )}
                </div>
            </div>
        </div >
    );
}
