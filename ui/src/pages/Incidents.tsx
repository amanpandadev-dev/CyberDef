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
        const matchesTactic = !tacticFilter || incident.primary_tactic === tacticFilter;
        return matchesSearch && matchesTactic;
    });

    const hasActiveFilters = statusFilter || priorityFilter || tacticFilter || searchTerm;

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString();
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-xl font-bold">Incidents</h1>
                    <p className="text-gray-400 mt-1">
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
                            <button onClick={() => updateFilter('priority', '')} className="ml-1 hover:text-white">
                                <X className="w-3 h-3" />
                            </button>
                        </span>
                    )}
                    {statusFilter && (
                        <span className="badge bg-surface-light text-white flex items-center gap-1">
                            Status: {statusLabels[statusFilter] || statusFilter}
                            <button onClick={() => updateFilter('status', '')} className="ml-1 hover:text-white">
                                <X className="w-3 h-3" />
                            </button>
                        </span>
                    )}
                    {tacticFilter && (
                        <span className="badge bg-purple-500/20 text-purple-300 flex items-center gap-1">
                            <Target className="w-3 h-3" />
                            {tacticFilter}
                            <button onClick={() => updateFilter('tactic', '')} className="ml-1 hover:text-white">
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
                            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-500" />
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
                </div>
            </div>

            {/* Incidents List */}
            <div className="card">
                {loading ? (
                    <div className="p-12 text-center">
                        <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full mx-auto" />
                        <p className="text-gray-400 mt-4">Loading incidents...</p>
                    </div>
                ) : filteredIncidents.length === 0 ? (
                    <div className="p-12 text-center">
                        <AlertTriangle className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                        <p className="text-gray-400">No incidents found</p>
                        <p className="text-sm text-gray-500 mt-1">
                            {hasActiveFilters ? 'Try adjusting your filters' : 'Upload and analyze log files to detect threats'}
                        </p>
                    </div>
                ) : (
                    <div className="divide-y divide-white/10">
                        {filteredIncidents.map((incident) => {
                            const sourceFiles = getSourceFiles(incident);
                            return (
                                <Link
                                    key={incident.incident_id}
                                    to={`/incidents/${incident.incident_id}`}
                                    className="block p-4 hover:bg-white/5 transition-colors"
                                >
                                    <div className="flex items-center justify-between">
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
                                                <h3 className="text-base font-medium normal-case" style={{ fontFamily: "'Titillium Web', sans-serif", textTransform: 'none' }}>{incident.title}</h3>
                                                <div className="flex items-center gap-4 mt-1 text-sm text-gray-400">
                                                    <span className="flex items-center gap-1">
                                                        <Clock className="w-4 h-4" />
                                                        {formatDate(incident.first_seen)}
                                                    </span>
                                                    {incident.primary_tactic && (
                                                        <span className="flex items-center gap-1">
                                                            <Target className="w-4 h-4" />
                                                            {incident.primary_tactic}
                                                        </span>
                                                    )}
                                                    <span className="flex items-center gap-1 text-yellow-400">
                                                        <Layers className="w-4 h-4" />
                                                        {incident.chunk_count} chunks
                                                    </span>
                                                    {/* Source File Display */}
                                                    {sourceFiles.length > 0 && (
                                                        <span className="flex items-center gap-1 text-blue-400">
                                                            <FileText className="w-4 h-4" />
                                                            {sourceFiles.length === 1
                                                                ? sourceFiles[0]
                                                                : `${sourceFiles.length} files`}
                                                        </span>
                                                    )}
                                                </div>
                                            </div>
                                        </div>

                                        <div className="flex items-center gap-4">
                                            <span className={`badge ${priorityStyles[incident.priority]}`}>
                                                {incident.priority.charAt(0).toUpperCase() + incident.priority.slice(1)}
                                            </span>
                                            <span className={`badge ${incident.status === 'new' ? 'bg-blue-500/20 text-blue-400' :
                                                incident.status === 'resolved' ? 'bg-green-500/20 text-green-400' :
                                                    incident.status === 'false_positive' ? 'bg-gray-500/20 text-gray-400' :
                                                        'bg-surface-light text-white'
                                                }`}>
                                                {statusLabels[incident.status] || incident.status}
                                            </span>
                                            <div className="text-right">
                                                <p className="text-sm text-gray-400">Confidence</p>
                                                <p className="font-semibold">{(incident.confidence * 100).toFixed(0)}%</p>
                                            </div>
                                            <ChevronRight className="w-5 h-5 text-gray-500" />
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
