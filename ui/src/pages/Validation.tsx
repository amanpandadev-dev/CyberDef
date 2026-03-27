import { useEffect, useState } from 'react';
import {
    Shield,
    CheckCircle,
    Database,
    Cpu,
    RefreshCw,
    Thermometer,
    Hash,
    AlertTriangle
} from 'lucide-react';
import { getValidationStats } from '../api';

interface ValidationStats {
    reproducibility: {
        status: string;
        description: string;
        cache_hit_rate: number;
        total_cache_entries: number;
    };
    determinism_settings: {
        temperature: number;
        max_temperature: number;
        model: string;
        description: string;
    };
    safeguards: string[];
    cache_stats: {
        hits: number;
        misses: number;
        hit_rate_percent: number;
        memory_entries: number;
    };
    agent_stats: Record<string, {
        agent: string;
        invocations: number;
        errors: number;
        success_rate: number;
    }>;
}

export default function Validation() {
    const [stats, setStats] = useState<ValidationStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchStats = async () => {
        setLoading(true);
        try {
            const data = await getValidationStats();
            setStats(data);
            setError(null);
        } catch (err) {
            setError('Failed to load validation metrics');
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchStats();
    }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center h-96">
                <div className="animate-spin w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full" />
            </div>
        );
    }

    if (error || !stats) {
        return (
            <div className="text-center py-12">
                <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <p className="text-gray-400">{error || 'No data available'}</p>
                <button onClick={fetchStats} className="btn btn-primary mt-4">
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold flex items-center gap-3">
                        <Shield className="w-8 h-8 text-green-400" />
                        Reproducibility Validation
                    </h1>
                    <p className="text-gray-400 mt-1">
                        Ensuring AI analysis is deterministic and not hallucinating
                    </p>
                </div>
                <button onClick={fetchStats} className="btn btn-secondary flex items-center gap-2">
                    <RefreshCw className="w-4 h-4" />
                    Refresh
                </button>
            </div>

            {/* Reproducibility Status Card */}
            <div className="card bg-gradient-to-r from-green-500/10 to-emerald-500/10 border-green-500/30">
                <div className="p-6">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <div className="w-16 h-16 bg-green-500/20 rounded-2xl flex items-center justify-center">
                                <CheckCircle className="w-8 h-8 text-green-400" />
                            </div>
                            <div>
                                <h2 className="text-2xl font-bold text-green-400">
                                    Reproducibility: {stats.reproducibility.status.toUpperCase()}
                                </h2>
                                <p className="text-gray-400 mt-1">
                                    {stats.reproducibility.description}
                                </p>
                            </div>
                        </div>
                        <div className="text-right">
                            <p className="text-4xl font-bold text-green-400">
                                {stats.reproducibility.cache_hit_rate.toFixed(1)}%
                            </p>
                            <p className="text-sm text-gray-400">Cache Hit Rate</p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {/* Temperature */}
                <div className="card p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <Thermometer className="w-6 h-6 text-blue-400" />
                        <h3 className="font-semibold">Temperature</h3>
                    </div>
                    <p className="text-3xl font-bold">{stats.determinism_settings.temperature}</p>
                    <p className="text-sm text-gray-400 mt-1">
                        Max: {stats.determinism_settings.max_temperature}
                    </p>
                    <p className="text-xs text-green-400 mt-2">
                        ✓ Low temperature for determinism
                    </p>
                </div>

                {/* Model */}
                <div className="card p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <Cpu className="w-6 h-6 text-purple-400" />
                        <h3 className="font-semibold">AI Model</h3>
                    </div>
                    <p className="text-xl font-bold truncate">{stats.determinism_settings.model}</p>
                    <p className="text-sm text-gray-400 mt-2">
                        {stats.determinism_settings.description}
                    </p>
                </div>

                {/* Cache Entries */}
                <div className="card p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <Database className="w-6 h-6 text-yellow-400" />
                        <h3 className="font-semibold">Cached Analyses</h3>
                    </div>
                    <p className="text-3xl font-bold">{stats.cache_stats.memory_entries}</p>
                    <p className="text-sm text-gray-400 mt-1">
                        {stats.cache_stats.hits} hits / {stats.cache_stats.misses} misses
                    </p>
                </div>

                {/* Hash-Based */}
                <div className="card p-6">
                    <div className="flex items-center gap-3 mb-4">
                        <Hash className="w-6 h-6 text-cyan-400" />
                        <h3 className="font-semibold">Content Hashing</h3>
                    </div>
                    <p className="text-xl font-bold text-green-400">SHA-256</p>
                    <p className="text-sm text-gray-400 mt-2">
                        Same input → Same cached result
                    </p>
                </div>
            </div>

            {/* Safeguards */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold flex items-center gap-2">
                        <Shield className="w-5 h-5 text-green-400" />
                        Active Safeguards Against Hallucination
                    </h3>
                </div>
                <div className="card-body">
                    <ul className="space-y-3">
                        {stats.safeguards.map((safeguard, index) => (
                            <li key={index} className="flex items-center gap-3">
                                <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                                <span className="text-gray-300">{safeguard}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            </div>

            {/* Agent Statistics */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold flex items-center gap-2">
                        <Cpu className="w-5 h-5 text-purple-400" />
                        Agent Performance
                    </h3>
                </div>
                <div className="card-body">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        {Object.entries(stats.agent_stats).map(([key, agent]) => (
                            <div key={key} className="p-4 bg-surface-dark rounded-lg">
                                <h4 className="font-medium text-primary-400 capitalize mb-2">
                                    {key} Agent
                                </h4>
                                <div className="space-y-1 text-sm">
                                    <div className="flex justify-between">
                                        <span className="text-gray-400">Invocations</span>
                                        <span>{agent.invocations}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-400">Errors</span>
                                        <span className={agent.errors > 0 ? 'text-red-400' : ''}>
                                            {agent.errors}
                                        </span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-400">Success Rate</span>
                                        <span className="text-green-400">
                                            {(agent.success_rate * 100).toFixed(0)}%
                                        </span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* How It Works */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">How Reproducibility Works</h3>
                </div>
                <div className="card-body">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="text-center p-6 bg-surface-dark rounded-lg">
                            <div className="w-12 h-12 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                                <span className="text-xl font-bold text-blue-400">1</span>
                            </div>
                            <h4 className="font-medium mb-2">Hash Input</h4>
                            <p className="text-sm text-gray-400">
                                SHA-256 hash computed from behavioral chunk summary
                            </p>
                        </div>
                        <div className="text-center p-6 bg-surface-dark rounded-lg">
                            <div className="w-12 h-12 bg-purple-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                                <span className="text-xl font-bold text-purple-400">2</span>
                            </div>
                            <h4 className="font-medium mb-2">Check Cache</h4>
                            <p className="text-sm text-gray-400">
                                If hash exists, return cached result (guaranteed same)
                            </p>
                        </div>
                        <div className="text-center p-6 bg-surface-dark rounded-lg">
                            <div className="w-12 h-12 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                                <span className="text-xl font-bold text-green-400">3</span>
                            </div>
                            <h4 className="font-medium mb-2">Low Temperature</h4>
                            <p className="text-sm text-gray-400">
                                Temperature ≤ 0.2 ensures near-deterministic AI outputs
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
