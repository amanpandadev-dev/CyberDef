import { useEffect, useState } from 'react';
import {
    TrendingUp,
    Users,
    AlertTriangle,
    Clock,
    Shield,
    FileText,
    RefreshCw,
    XCircle
} from 'lucide-react';

const API_BASE_URL = 'http://localhost:8000/api/v1';

interface ActorProfile {
    profile_id: string;
    primary_ip: string | null;
    all_ips: string[];
    username: string | null;
    first_seen: string | null;
    last_seen: string | null;
    total_events: number;
    total_denials: number;
    unique_targets: number;
    active_days: number;
    risk_score: number;
    risk_factors: string[];
    files_count: number;
}

interface RollupData {
    status: string;
    message?: string;
    rollup_id?: string;
    days_covered?: number;
    chunks_analyzed?: number;
    files_analyzed?: number;
    actor_profiles?: ActorProfile[];
    high_risk_actors?: string[];
    cross_file_patterns?: any[];
    created_at?: string;
}

export default function Rollups() {
    const [data, setData] = useState<RollupData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchRollups = async () => {
        setLoading(true);
        try {
            const response = await fetch(`${API_BASE_URL}/rollups`);
            if (!response.ok) throw new Error('Failed to fetch rollup data');
            const result = await response.json();
            setData(result);
            setError(null);
        } catch (err) {
            setError('Failed to load rollup analysis');
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchRollups();
    }, []);

    const getRiskColor = (score: number) => {
        if (score >= 70) return 'text-red-400 bg-red-500/20';
        if (score >= 40) return 'text-yellow-400 bg-yellow-500/20';
        return 'text-green-400 bg-green-500/20';
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <RefreshCw className="w-8 h-8 animate-spin text-primary-400" />
            </div>
        );
    }

    if (error) {
        return (
            <div className="card p-8 text-center">
                <XCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <p className="text-red-400">{error}</p>
                <button onClick={fetchRollups} className="btn btn-primary mt-4">
                    Try Again
                </button>
            </div>
        );
    }

    if (!data || data.status === 'no_data') {
        return (
            <div className="space-y-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold">Long-Horizon Rollup Analysis</h1>
                        <p className="text-gray-400">Cross-file threat correlation over time</p>
                    </div>
                </div>
                <div className="card p-8 text-center">
                    <TrendingUp className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold mb-2">No Data Available</h3>
                    <p className="text-gray-400 mb-4">
                        {data?.message || 'Analyze some log files to start cross-file correlation analysis.'}
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold">Long-Horizon Rollup Analysis</h1>
                    <p className="text-gray-400">Cross-file threat correlation over extended time periods</p>
                </div>
                <button onClick={fetchRollups} className="btn btn-secondary flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" />
                    Refresh
                </button>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="card text-center">
                    <div className="card-body">
                        <FileText className="w-8 h-8 text-blue-400 mx-auto mb-2" />
                        <p className="text-3xl font-bold">{data.files_analyzed || 0}</p>
                        <p className="text-sm text-gray-400">Files Analyzed</p>
                    </div>
                </div>
                <div className="card text-center">
                    <div className="card-body">
                        <Clock className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
                        <p className="text-3xl font-bold">{data.days_covered || 0}</p>
                        <p className="text-sm text-gray-400">Days Covered</p>
                    </div>
                </div>
                <div className="card text-center">
                    <div className="card-body">
                        <Users className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                        <p className="text-3xl font-bold">{data.actor_profiles?.length || 0}</p>
                        <p className="text-sm text-gray-400">Actors Tracked</p>
                    </div>
                </div>
                <div className="card text-center">
                    <div className="card-body">
                        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-2" />
                        <p className="text-3xl font-bold">{data.high_risk_actors?.length || 0}</p>
                        <p className="text-sm text-gray-400">High Risk Actors</p>
                    </div>
                </div>
            </div>

            {/* High Risk Actors Alert */}
            {data.high_risk_actors && data.high_risk_actors.length > 0 && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                    <div className="flex items-center gap-3">
                        <AlertTriangle className="w-6 h-6 text-red-400" />
                        <div>
                            <h3 className="font-semibold text-red-400">High Risk Actors Detected</h3>
                            <p className="text-sm text-gray-400">
                                {data.high_risk_actors.join(', ')}
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Actor Profiles */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold flex items-center gap-2">
                        <Users className="w-5 h-5 text-purple-400" />
                        Actor Profiles ({data.actor_profiles?.length || 0})
                    </h3>
                </div>
                <div className="card-body">
                    {data.actor_profiles && data.actor_profiles.length > 0 ? (
                        <div className="space-y-4">
                            {data.actor_profiles.slice(0, 10).map((actor) => (
                                <div key={actor.profile_id} className="bg-surface-dark rounded-lg p-4">
                                    <div className="flex items-start justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-lg bg-purple-500/20 flex items-center justify-center">
                                                <Users className="w-5 h-5 text-purple-400" />
                                            </div>
                                            <div>
                                                <p className="font-medium">
                                                    {actor.primary_ip || actor.username || 'Unknown Actor'}
                                                </p>
                                                <div className="flex gap-3 text-xs text-gray-400 mt-1">
                                                    <span>{actor.total_events} events</span>
                                                    <span>{actor.unique_targets} targets</span>
                                                    <span>{actor.files_count} files</span>
                                                </div>
                                            </div>
                                        </div>
                                        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getRiskColor(actor.risk_score)}`}>
                                            Risk: {actor.risk_score.toFixed(0)}
                                        </span>
                                    </div>

                                    {actor.risk_factors.length > 0 && (
                                        <div className="mt-3 flex flex-wrap gap-2">
                                            {actor.risk_factors.map((factor, idx) => (
                                                <span key={idx} className="text-xs px-2 py-1 bg-red-500/20 text-red-300 rounded">
                                                    {factor}
                                                </span>
                                            ))}
                                        </div>
                                    )}

                                    <div className="mt-3 grid grid-cols-4 gap-4 text-sm">
                                        <div>
                                            <span className="text-gray-400">First Seen:</span>
                                            <p className="font-medium">
                                                {actor.first_seen ? new Date(actor.first_seen).toLocaleDateString() : 'N/A'}
                                            </p>
                                        </div>
                                        <div>
                                            <span className="text-gray-400">Last Seen:</span>
                                            <p className="font-medium">
                                                {actor.last_seen ? new Date(actor.last_seen).toLocaleDateString() : 'N/A'}
                                            </p>
                                        </div>
                                        <div>
                                            <span className="text-gray-400">Active Days:</span>
                                            <p className="font-medium">{actor.active_days}</p>
                                        </div>
                                        <div>
                                            <span className="text-gray-400">Denials:</span>
                                            <p className={`font-medium ${actor.total_denials > 0 ? 'text-red-400' : ''}`}>
                                                {actor.total_denials}
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="text-gray-400 text-center py-8">No actor profiles available</p>
                    )}
                </div>
            </div>

            {/* How It Works */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">How Long-Horizon Rollup Analysis Works</h3>
                </div>
                <div className="card-body text-sm text-gray-400">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="flex items-start gap-3">
                            <div className="w-8 h-8 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                                <FileText className="w-4 h-4 text-blue-400" />
                            </div>
                            <div>
                                <p className="font-medium text-white mb-1">1. Cross-File Correlation</p>
                                <p>Chunks from all analyzed files are stored and correlated to find patterns spanning multiple sources.</p>
                            </div>
                        </div>
                        <div className="flex items-start gap-3">
                            <div className="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center flex-shrink-0">
                                <Users className="w-4 h-4 text-purple-400" />
                            </div>
                            <div>
                                <p className="font-medium text-white mb-1">2. Actor Profiling</p>
                                <p>Build extended profiles for each actor tracking their behavior, targets, and activity patterns over time.</p>
                            </div>
                        </div>
                        <div className="flex items-start gap-3">
                            <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center flex-shrink-0">
                                <Shield className="w-4 h-4 text-red-400" />
                            </div>
                            <div>
                                <p className="font-medium text-white mb-1">3. Risk Assessment</p>
                                <p>Calculate risk scores based on event counts, denial rates, target diversity, and temporal patterns.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
