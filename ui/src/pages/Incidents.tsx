import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
    AlertTriangle,
    Clock,
    Target,
    ChevronRight,
    Search,
    X,
    Layers,
    FileText
} from 'lucide-react';
import { getIncidents, getFiles } from '../api';
import { formatISTDateTime } from '../utils/datetime';

interface IncidentSummary {
    incident_id: string;
    title: string;
    status: string;
    priority: string;
    first_seen: string;
    last_seen: string;
    chunk_count: number;
    confidence: number;
    primary_tactic: string | null;
    file_ids?: string[];
    raw_log?: string | null;
    source_ip?: string | null;
    destination_ip?: string | null;
    suspicious?: boolean;
    suspicious_indicator?: string | null;
    attack_name?: string | null;
    brief_description?: string | null;
    recommended_action?: string | null;
    confidence_score?: number;
    mitre_tactic?: string | null;
    mitre_technique?: string | null;
}

interface FileInfo {
    file_id: string;
    filename?: string;
    original_filename?: string;
}

const priorityStyles: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    informational: 'badge-info',
};

const statusLabels: Record<string, string> = {
    new: 'New',
    triaged: 'Triaged',
    investigating: 'Investigating',
    confirmed: 'Confirmed',
    false_positive: 'False Positive',
    resolved: 'Resolved',
    closed: 'Closed',
};

export default function Incidents() {
    const [searchParams, setSearchParams] = useSearchParams();
    const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
    const [files, setFiles] = useState<FileInfo[]>([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    // Get filters from URL params
    const statusFilter = searchParams.get('status') || '';
    const priorityFilter = searchParams.get('priority') || '';
    const tacticFilter = searchParams.get('tactic') || '';
    const fileFilter = searchParams.get('file_id') || '';

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true);
            try {
                const [incidentsData, filesData] = await Promise.all([
                    getIncidents(
                        statusFilter || undefined,
                        priorityFilter || undefined
                    ),
                    getFiles().catch(() => [])
                ]);
                setIncidents(incidentsData);
                setFiles(filesData);
            } catch (error) {
                console.error('Failed to fetch data:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [statusFilter, priorityFilter]);

    // Helper to get filename from file_id
    const getFilename = (fileId: string): string => {
        const file = files.find(f => f.file_id === fileId);
        if (file) {
            return file.filename || file.original_filename || fileId.slice(0, 8);
        }
        return fileId.slice(0, 8);
    };

    // Get source files for incident
    const getSourceFiles = (incident: IncidentSummary): string[] => {
        if (!incident.file_ids || incident.file_ids.length === 0) return [];
        return incident.file_ids.map(fid => getFilename(fid));
    };

    // Update URL params when filters change
    const updateFilter = (key: string, value: string) => {
        const newParams = new URLSearchParams(searchParams);
        if (value) {
            newParams.set(key, value);
        } else {
            newParams.delete(key);
        }
        setSearchParams(newParams);
    };

    // Clear all filters
    const clearFilters = () => {
        setSearchParams({});
        setSearchTerm('');
    };

    // Filter incidents by search and tactic (tactic filtering is done client-side)
    const filteredIncidents = incidents.filter((incident) => {
        const matchesSearch = incident.title.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesTactic = !tacticFilter || incident.primary_tactic === tacticFilter || incident.mitre_tactic === tacticFilter;
        const matchesFile = !fileFilter || (incident.file_ids || []).map(String).includes(fileFilter);
        return matchesSearch && matchesTactic && matchesFile;
    });

    const hasActiveFilters = statusFilter || priorityFilter || tacticFilter || fileFilter || searchTerm;

    const formatDate = (dateStr: string) => {
        return formatISTDateTime(dateStr);
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-xl font-bold">Incidents</h1>
                    <p className="text-slate-600 mt-1">
                        Review and manage security incidents
                    </p>
                </div>
                {hasActiveFilters && (
                    <button
                        onClick={clearFilters}
                        className="btn btn-secondary flex items-center gap-2"
                    >
                        <X className="w-4 h-4" />
                        Clear Filters
                    </button>
                )}
            </div>

            {/* Active Filters Display */}
            {hasActiveFilters && (
                <div className="flex flex-wrap gap-2">
                    {priorityFilter && (
                        <span className={`badge ${priorityStyles[priorityFilter]} flex items-center gap-1`}>
                            Priority: {priorityFilter}
                            <button onClick={() => updateFilter('priority', '')} className="ml-1 hover:text-primary-500">
                                <X className="w-3 h-3" />
                            </button>
                        </span>
                    )}
                    {statusFilter && (
                        <span className="badge bg-surface-light text-slate-800 flex items-center gap-1">
                            Status: {statusLabels[statusFilter] || statusFilter}
                            <button onClick={() => updateFilter('status', '')} className="ml-1 hover:text-primary-500">
                                <X className="w-3 h-3" />
                            </button>
                        </span>
                    )}
                    {tacticFilter && (
                        <span className="badge bg-purple-500/20 text-purple-300 flex items-center gap-1">
                            <Target className="w-3 h-3" />
                            {tacticFilter}
                            <button onClick={() => updateFilter('tactic', '')} className="ml-1 hover:text-primary-500">
                                <X className="w-3 h-3" />
                            </button>
                        </span>
                    )}
                    {fileFilter && (
                        <span className="badge bg-blue-100 text-blue-700 flex items-center gap-1">
                            File: {getFilename(fileFilter)}
                            <button onClick={() => updateFilter('file_id', '')} className="ml-1 hover:text-primary-500">
                                <X className="w-3 h-3" />
                            </button>
                        </span>
                    )}
                </div>
            )}

            {/* Filters */}
            <div className="card">
                <div className="p-4 flex flex-wrap gap-4">
                    <div className="flex-1 min-w-[200px]">
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400" />
                            <input
                                type="text"
                                placeholder="Search incidents..."
                                className="input pl-10"
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                            />
                        </div>
                    </div>

                    <select
                        className="input w-auto"
                        value={statusFilter}
                        onChange={(e) => updateFilter('status', e.target.value)}
                    >
                        <option value="">All Statuses</option>
                        <option value="new">New</option>
                        <option value="triaged">Triaged</option>
                        <option value="investigating">Investigating</option>
                        <option value="confirmed">Confirmed</option>
                        <option value="false_positive">False Positive</option>
                        <option value="resolved">Resolved</option>
                    </select>

                    <select
                        className="input w-auto"
                        value={priorityFilter}
                        onChange={(e) => updateFilter('priority', e.target.value)}
                    >
                        <option value="">All Priorities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>

                    <select
                        className="input w-auto"
                        value={fileFilter}
                        onChange={(e) => updateFilter('file_id', e.target.value)}
                    >
                        <option value="">All Log Files</option>
                        {files.map((file) => (
                            <option key={file.file_id} value={file.file_id}>
                                {file.filename || file.original_filename || file.file_id.slice(0, 8)}
                            </option>
                        ))}
                    </select>
                </div>
            </div>

            {/* Incidents List */}
            <div className="card">
                {loading ? (
                    <div className="p-12 text-center">
                        <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full mx-auto" />
                        <p className="text-slate-500 mt-4">Loading incidents...</p>
                    </div>
                ) : filteredIncidents.length === 0 ? (
                    <div className="p-12 text-center">
                        <AlertTriangle className="w-12 h-12 text-slate-500 mx-auto mb-4" />
                        <p className="text-slate-500">No incidents found</p>
                        <p className="text-sm text-slate-500 mt-1">
                            {hasActiveFilters ? 'Try adjusting your filters' : 'Upload and analyze log files to detect threats'}
                        </p>
                    </div>
                ) : (
                    <div className="divide-y divide-slate-200">
                        {filteredIncidents.map((incident) => {
                            const sourceFiles = getSourceFiles(incident);
                            return (
                                <Link
                                    key={incident.incident_id}
                                    to={`/incidents/${incident.incident_id}`}
                                    className="block p-4 hover:bg-slate-50 transition-colors"
                                >
                                    <div className="space-y-4">
                                        <div className="flex flex-wrap items-center justify-between gap-4">
                                            <div className="flex items-center gap-4">
                                                <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${incident.priority === 'critical' ? 'bg-red-500/20' :
                                                    incident.priority === 'high' ? 'bg-orange-500/20' :
                                                        incident.priority === 'medium' ? 'bg-yellow-500/20' :
                                                            'bg-green-500/20'
                                                    }`}>
                                                    <AlertTriangle className={`w-6 h-6 ${incident.priority === 'critical' ? 'text-red-400' :
                                                        incident.priority === 'high' ? 'text-orange-400' :
                                                            incident.priority === 'medium' ? 'text-yellow-400' :
                                                                'text-green-400'
                                                        }`} />
                                                </div>
                                                <div>
                                                    <h3 className="text-base font-semibold text-slate-900 normal-case" style={{ textTransform: 'none' }}>
                                                        {incident.attack_name || incident.title}
                                                    </h3>
                                                    <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-slate-500">
                                                        <span className="flex items-center gap-1">
                                                            <Clock className="w-3.5 h-3.5" />
                                                            {formatDate(incident.first_seen)}
                                                        </span>
                                                        <span className="flex items-center gap-1 text-yellow-400">
                                                            <Layers className="w-3.5 h-3.5" />
                                                            {incident.chunk_count} chunks
                                                        </span>
                                                        {sourceFiles.length > 0 && (
                                                            <span className="flex items-center gap-1 text-blue-400">
                                                                <FileText className="w-3.5 h-3.5" />
                                                                {sourceFiles.length === 1 ? sourceFiles[0] : `${sourceFiles.length} files`}
                                                            </span>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>

                                            <div className="flex items-center gap-3">
                                                <span className={`badge ${priorityStyles[incident.priority]}`}>
                                                    {incident.priority}
                                                </span>
                                                <span className={`badge ${incident.status === 'new' ? 'bg-blue-500/20 text-blue-400' :
                                                    incident.status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                                                        incident.status === 'false_positive' ? 'bg-gray-200 text-gray-700' :
                                                            'bg-slate-100 text-slate-700'
                                                    }`}>
                                                    {statusLabels[incident.status] || incident.status}
                                                </span>
                                                <ChevronRight className="w-5 h-5 text-slate-400" />
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 text-xs">
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Raw Log: </span><span className="text-slate-800">{incident.raw_log || 'N/A'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Source_IP: </span><span className="text-slate-800">{incident.source_ip || 'N/A'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Destination_IP: </span><span className="text-slate-800">{incident.destination_ip || 'N/A'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Suspicious: </span><span className={`${incident.suspicious ? 'text-red-600' : 'text-emerald-600'}`}>{incident.suspicious ? 'Yes' : 'No'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Suspicious Indicator: </span><span className="text-slate-800">{incident.suspicious_indicator || 'null'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Attack Name: </span><span className="text-slate-800">{incident.attack_name || incident.title}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Brief Description: </span><span className="text-slate-800">{incident.brief_description || 'N/A'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Recommended Action: </span><span className="text-slate-800">{incident.recommended_action || 'N/A'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Confidence (1-10): </span><span className="text-indigo-600 font-semibold">{incident.confidence_score ?? Math.max(1, Math.min(10, Math.round((incident.confidence || 0) * 10)))}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Mitre Tactic: </span><span className="text-slate-800">{incident.mitre_tactic || incident.primary_tactic || 'N/A'}</span></div>
                                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-2.5"><span className="text-slate-500">Mitre Technique: </span><span className="text-slate-800">{incident.mitre_technique || 'N/A'}</span></div>
                                        </div>
                                    </div>
                                </Link>
                            );
                        })}
                    </div>
                )}
            </div>
        </div>
    );
}
