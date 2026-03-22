import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
    ArrowLeft,
    AlertTriangle,
    Clock,
    Target,
    User,
    Server,
    Shield,
    FileText,
    CheckCircle,
    Layers,
    Database
} from 'lucide-react';
import { getIncident, updateIncident, getFiles } from '../api';

interface Incident {
    incident_id: string;
    title: string;
    description: string;
    status: string;
    priority: string;
    first_seen: string;
    last_seen: string;
    primary_actor_ip: string | null;
    actor_ips: string[];
    affected_hosts: string[];
    chunk_ids?: string[];
    file_ids?: string[];
    mitre_techniques: Array<{
        technique_id: string;
        technique_name: string;
        tactic: string;
        confidence: number;
    }>;
    primary_tactic: string | null;
    overall_confidence: number;
    executive_summary: string;
    technical_summary: string;
    recommended_actions: string[];
    timeline: Array<{
        timestamp: string;
        event_type: string;
        description: string;
    }>;
}

interface FileInfo {
    file_id: string;
    filename?: string;
    original_filename?: string;
}

const priorityColors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-green-500',
    informational: 'bg-blue-500',
};

export default function IncidentDetail() {
    const { id } = useParams<{ id: string }>();
    const [incident, setIncident] = useState<Incident | null>(null);
    const [files, setFiles] = useState<FileInfo[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            if (!id) return;
            try {
                const [incidentData, filesData] = await Promise.all([
                    getIncident(id),
                    getFiles().catch(() => [])
                ]);
                setIncident(incidentData);
                setFiles(filesData);
            } catch (error) {
                console.error('Failed to fetch incident:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
    }, [id]);

    // Helper to get filename from file_id
    const getFilename = (fileId: string): string => {
        const file = files.find(f => f.file_id === fileId);
        if (file) {
            return file.filename || file.original_filename || fileId.slice(0, 8);
        }
        return fileId.slice(0, 8);
    };

    const handleStatusChange = async (newStatus: string) => {
        if (!id || !incident) return;
        try {
            const updated = await updateIncident(id, { status: newStatus });
            setIncident(updated);
        } catch (error) {
            console.error('Failed to update status:', error);
        }
    };

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString();
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full" />
            </div>
        );
    }

    if (!incident) {
        return (
            <div className="text-center py-12">
                <AlertTriangle className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                <p className="text-gray-400">Incident not found</p>
            </div>
        );
    }

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <Link
                        to="/incidents"
                        className="flex items-center gap-2 text-gray-400 hover:text-white mb-4 transition-colors"
                    >
                        <ArrowLeft className="w-4 h-4" />
                        Back to Incidents
                    </Link>
                    <h1 className="text-3xl font-bold">{incident.title}</h1>
                    <div className="flex items-center gap-4 mt-2">
                        <span className={`badge ${incident.priority === 'critical' ? 'badge-critical' :
                            incident.priority === 'high' ? 'badge-high' :
                                incident.priority === 'medium' ? 'badge-medium' :
                                    'badge-low'
                            }`}>
                            {incident.priority.toUpperCase()}
                        </span>
                        <span className="text-gray-400">
                            <Clock className="w-4 h-4 inline mr-1" />
                            {formatDate(incident.first_seen)}
                        </span>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    <select
                        className="input w-auto"
                        value={incident.status}
                        onChange={(e) => handleStatusChange(e.target.value)}
                    >
                        <option value="new">New</option>
                        <option value="triaged">Triaged</option>
                        <option value="investigating">Investigating</option>
                        <option value="confirmed">Confirmed</option>
                        <option value="false_positive">False Positive</option>
                        <option value="resolved">Resolved</option>
                    </select>
                </div>
            </div>

            {/* Confidence Bar */}
            <div className="card p-6">
                <div className="flex items-center justify-between mb-2">
                    <span className="text-gray-400">Overall Confidence</span>
                    <span className="font-bold text-2xl">
                        {(incident.overall_confidence * 100).toFixed(0)}%
                    </span>
                </div>
                <div className="h-3 bg-surface-dark rounded-full overflow-hidden">
                    <div
                        className={`h-full ${priorityColors[incident.priority]} transition-all duration-500`}
                        style={{ width: `${incident.overall_confidence * 100}%` }}
                    />
                </div>
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left Column */}
                <div className="lg:col-span-2 space-y-6">
                    {/* Summaries */}
                    <div className="card">
                        <div className="card-header">
                            <h3 className="font-semibold flex items-center gap-2">
                                <FileText className="w-5 h-5 text-primary-400" />
                                Analysis Summary
                            </h3>
                        </div>
                        <div className="card-body space-y-6">
                            {incident.executive_summary && (
                                <div>
                                    <h4 className="font-medium text-gray-300 mb-2">Executive Summary</h4>
                                    <p className="text-gray-400">{incident.executive_summary}</p>
                                </div>
                            )}
                            {incident.technical_summary && (
                                <div>
                                    <h4 className="font-medium text-gray-300 mb-2">Technical Summary</h4>
                                    <p className="text-gray-400">{incident.technical_summary}</p>
                                </div>
                            )}
                            <div>
                                <h4 className="font-medium text-gray-300 mb-2">Description</h4>
                                <p className="text-gray-400 whitespace-pre-line">{incident.description}</p>
                            </div>
                        </div>
                    </div>

                    {/* MITRE Mapping */}
                    {incident.mitre_techniques.length > 0 && (
                        <div className="card">
                            <div className="card-header">
                                <h3 className="font-semibold flex items-center gap-2">
                                    <Target className="w-5 h-5 text-purple-400" />
                                    MITRE ATT&CK Mapping
                                </h3>
                            </div>
                            <div className="card-body">
                                <div className="space-y-4">
                                    {incident.mitre_techniques.map((technique, index) => (
                                        <div
                                            key={index}
                                            className="p-4 bg-surface-dark rounded-lg border border-white/10"
                                        >
                                            <div className="flex items-center justify-between">
                                                <div>
                                                    <span className="text-primary-400 font-mono font-bold">
                                                        {technique.technique_id}
                                                    </span>
                                                    <span className="mx-2 text-gray-500">|</span>
                                                    <span className="font-medium">{technique.technique_name}</span>
                                                </div>
                                                <span className="text-sm text-gray-400">
                                                    {(technique.confidence * 100).toFixed(0)}% confidence
                                                </span>
                                            </div>
                                            <p className="text-sm text-gray-500 mt-1">
                                                Tactic: {technique.tactic}
                                            </p>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Timeline */}
                    {incident.timeline.length > 0 && (
                        <div className="card">
                            <div className="card-header">
                                <h3 className="font-semibold flex items-center gap-2">
                                    <Clock className="w-5 h-5 text-blue-400" />
                                    Timeline
                                </h3>
                            </div>
                            <div className="card-body">
                                <div className="space-y-4">
                                    {incident.timeline.map((event, index) => (
                                        <div key={index} className="flex gap-4">
                                            <div className="flex flex-col items-center">
                                                <div className="w-3 h-3 bg-primary-500 rounded-full" />
                                                {index < incident.timeline.length - 1 && (
                                                    <div className="w-0.5 h-full bg-white/10" />
                                                )}
                                            </div>
                                            <div className="pb-4">
                                                <p className="text-sm text-gray-400">
                                                    {formatDate(event.timestamp)}
                                                </p>
                                                <p className="font-medium mt-1">{event.description}</p>
                                                <span className="text-xs text-gray-500">{event.event_type}</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* Right Column */}
                <div className="space-y-6">
                    {/* Actor Info */}
                    <div className="card">
                        <div className="card-header">
                            <h3 className="font-semibold flex items-center gap-2">
                                <User className="w-5 h-5 text-orange-400" />
                                Actor Information
                            </h3>
                        </div>
                        <div className="card-body space-y-4">
                            {incident.primary_actor_ip && (
                                <div>
                                    <p className="text-sm text-gray-400">Primary IP</p>
                                    <code className="text-lg font-mono">{incident.primary_actor_ip}</code>
                                </div>
                            )}
                            {incident.actor_ips.length > 1 && (
                                <div>
                                    <p className="text-sm text-gray-400 mb-2">All Actor IPs</p>
                                    <div className="space-y-1">
                                        {incident.actor_ips.map((ip, index) => (
                                            <code key={index} className="block text-sm font-mono text-gray-300">
                                                {ip}
                                            </code>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Affected Hosts */}
                    {incident.affected_hosts.length > 0 && (
                        <div className="card">
                            <div className="card-header">
                                <h3 className="font-semibold flex items-center gap-2">
                                    <Server className="w-5 h-5 text-green-400" />
                                    Affected Hosts
                                </h3>
                            </div>
                            <div className="card-body">
                                <div className="space-y-1">
                                    {incident.affected_hosts.slice(0, 10).map((host, index) => (
                                        <code key={index} className="block text-sm font-mono text-gray-300">
                                            {host}
                                        </code>
                                    ))}
                                    {incident.affected_hosts.length > 10 && (
                                        <p className="text-sm text-gray-500">
                                            +{incident.affected_hosts.length - 10} more
                                        </p>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Source Files - NEW SECTION */}
                    <div className="card">
                        <div className="card-header">
                            <h3 className="font-semibold flex items-center gap-2">
                                <Database className="w-5 h-5 text-blue-400" />
                                Source Evidence
                            </h3>
                        </div>
                        <div className="card-body">
                            <div className="space-y-3">
                                {/* Source Files */}
                                <div>
                                    <p className="text-sm text-gray-400 mb-2">Source Log Files</p>
                                    {incident.file_ids && incident.file_ids.length > 0 ? (
                                        <div className="space-y-1">
                                            {incident.file_ids.map((fileId, index) => (
                                                <div key={index} className="flex items-center gap-2 p-2 bg-surface-dark rounded-lg">
                                                    <FileText className="w-4 h-4 text-blue-400" />
                                                    <code className="text-sm font-mono text-blue-300">
                                                        {getFilename(fileId)}
                                                    </code>
                                                </div>
                                            ))}
                                        </div>
                                    ) : (
                                        <p className="text-sm text-gray-500 italic">No source files linked</p>
                                    )}
                                </div>

                                {/* Chunk Count */}
                                <div>
                                    <p className="text-sm text-gray-400 mb-2">Behavioral Chunks</p>
                                    <div className="flex items-center gap-2 p-2 bg-surface-dark rounded-lg">
                                        <Layers className="w-4 h-4 text-yellow-400" />
                                        <span className="font-medium text-yellow-300">
                                            {incident.chunk_ids?.length || 0} chunks analyzed
                                        </span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Recommended Actions */}
                    {incident.recommended_actions.length > 0 && (
                        <div className="card">
                            <div className="card-header">
                                <h3 className="font-semibold flex items-center gap-2">
                                    <Shield className="w-5 h-5 text-yellow-400" />
                                    Recommended Actions
                                </h3>
                            </div>
                            <div className="card-body">
                                <ul className="space-y-3">
                                    {incident.recommended_actions.map((action, index) => (
                                        <li key={index} className="flex items-start gap-3">
                                            <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                                            <span className="text-gray-300">{action}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
