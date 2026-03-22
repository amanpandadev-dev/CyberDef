import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
    AlertTriangle,
    Shield,
    FileText,
    Activity,
    TrendingUp,
    Clock,
    Target,
    Upload,
    AlertCircle,
    Info,
    Zap
} from 'lucide-react';
import {
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
    PieChart,
    Pie,
    Cell,
    LineChart,
    Line,
    BarChart,
    Bar
} from 'recharts';
import { healthCheck, getIncidentStats, getFiles, getIncidents } from '../api';

interface Stats {
    total_incidents: number;
    by_status: Record<string, number>;
    by_priority: Record<string, number>;
}

const PRIORITY_COLORS = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#22c55e',
    informational: '#3b82f6',
};

const SEVERITY_COLORS = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#22c55e',
    info: '#3b82f6',
};

export default function Dashboard() {
    const [health, setHealth] = useState<any>(null);
    const [stats, setStats] = useState<Stats | null>(null);
    const [files, setFiles] = useState<any[]>([]);
    const [incidents, setIncidents] = useState<any[]>([]);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [healthData, statsData, filesData, incidentsData] = await Promise.all([
                    healthCheck().catch(() => null),
                    getIncidentStats().catch(() => ({ total_incidents: 0, by_status: {}, by_priority: {} })),
                    getFiles().catch(() => []),
                    getIncidents().catch(() => [])
                ]);
                setHealth(healthData);
                setStats(statsData);
                setFiles(filesData);
                setIncidents(incidentsData);
            } catch (error) {
                console.error('Failed to fetch dashboard data:', error);
            }
        };

        fetchData();
        // Auto-refresh every 30 seconds
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    // Process data for charts
    const priorityData = stats?.by_priority
        ? Object.entries(stats.by_priority).map(([name, value]) => ({
            name: name.charAt(0).toUpperCase() + name.slice(1),
            value,
            color: PRIORITY_COLORS[name as keyof typeof PRIORITY_COLORS] || '#6b7280',
        }))
        : [];

    // Compute severity distribution from incidents
    const severityData = (() => {
        const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        incidents.forEach((inc) => {
            const severity = (inc.severity || 'medium').toLowerCase();
            if (counts[severity] !== undefined) {
                counts[severity] += 1;
            } else {
                counts.medium += 1;
            }
        });
        return Object.entries(counts)
            .filter(([_, value]) => value > 0)
            .map(([name, value]) => ({
                name: name.charAt(0).toUpperCase() + name.slice(1),
                value,
                color: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS] || '#6b7280',
            }));
    })();

    // Compute Timeline Data (incidents by date)
    const timelineData = incidents.reduce((acc: any[], incident) => {
        const date = new Date(incident.first_seen).toLocaleDateString();
        const existing = acc.find(item => item.date === date);
        if (existing) {
            existing.incidents += 1;
        } else {
            acc.push({ date, incidents: 1 });
        }
        return acc;
    }, []).sort((a: any, b: any) => new Date(a.date).getTime() - new Date(b.date).getTime());

    // Compute unique tactics count
    const uniqueTactics = new Set(incidents.map(i => i.primary_tactic).filter(Boolean)).size;

    // MITRE tactics distribution
    const mitreData = (() => {
        const counts: Record<string, number> = {};
        incidents.forEach((inc) => {
            if (inc.primary_tactic) {
                counts[inc.primary_tactic] = (counts[inc.primary_tactic] || 0) + 1;
            }
        });
        return Object.entries(counts)
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 8); // Top 8 tactics
    })();

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold">Security Dashboard</h1>
                    <p className="text-gray-400 mt-1">AI-powered threat intelligence at a glance</p>
                </div>
                <div className="flex items-center gap-4">
                    <div className={`flex items-center gap-2 px-4 py-2 rounded-full ${health?.status === 'healthy'
                        ? 'bg-green-500/20 text-green-400'
                        : 'bg-yellow-500/20 text-yellow-400'
                        }`}>
                        <div className={`w-2 h-2 rounded-full ${health?.status === 'healthy' ? 'bg-green-400' : 'bg-yellow-400'
                            } animate-pulse`} />
                        <span className="text-sm font-medium">
                            {health?.status === 'healthy' ? 'System Healthy' : 'Degraded'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
                <Link to="/incidents" className="stat-card hover:border-primary-500/50 transition-colors cursor-pointer">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Total Incidents</p>
                            <p className="text-3xl font-bold mt-1">{stats?.total_incidents || 0}</p>
                        </div>
                        <div className="w-12 h-12 bg-primary-500/20 rounded-xl flex items-center justify-center">
                            <AlertTriangle className="w-6 h-6 text-primary-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <TrendingUp className="w-4 h-4 text-green-400" />
                        <span className="text-gray-400">Click to view all →</span>
                    </div>
                </Link>

                <Link to="/incidents?priority=critical" className="stat-card border-red-500/30 hover:border-red-500/70 transition-colors cursor-pointer">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Critical</p>
                            <p className="text-3xl font-bold mt-1 text-red-400">
                                {stats?.by_priority?.critical || 0}
                            </p>
                        </div>
                        <div className="w-12 h-12 bg-red-500/20 rounded-xl flex items-center justify-center">
                            <AlertCircle className="w-6 h-6 text-red-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <Clock className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-400">Immediate action →</span>
                    </div>
                </Link>

                <Link to="/incidents?priority=high" className="stat-card border-orange-500/30 hover:border-orange-500/70 transition-colors cursor-pointer">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">High</p>
                            <p className="text-3xl font-bold mt-1 text-orange-400">
                                {stats?.by_priority?.high || 0}
                            </p>
                        </div>
                        <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center">
                            <Zap className="w-6 h-6 text-orange-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <span className="text-gray-400">Needs attention →</span>
                    </div>
                </Link>

                <Link to="/incidents?priority=medium" className="stat-card border-yellow-500/30 hover:border-yellow-500/70 transition-colors cursor-pointer">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Medium</p>
                            <p className="text-3xl font-bold mt-1 text-yellow-400">
                                {stats?.by_priority?.medium || 0}
                            </p>
                        </div>
                        <div className="w-12 h-12 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                            <Shield className="w-6 h-6 text-yellow-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <span className="text-gray-400">Monitor closely →</span>
                    </div>
                </Link>

                <Link to="/incidents?priority=low" className="stat-card border-green-500/30 hover:border-green-500/70 transition-colors cursor-pointer">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Low/Info</p>
                            <p className="text-3xl font-bold mt-1 text-green-400">
                                {(stats?.by_priority?.low || 0) + (stats?.by_priority?.informational || 0)}
                            </p>
                        </div>
                        <div className="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                            <Info className="w-6 h-6 text-green-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <span className="text-gray-400">For awareness →</span>
                    </div>
                </Link>
            </div>

            {/* Secondary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="stat-card">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Files Analyzed</p>
                            <p className="text-3xl font-bold mt-1">{files.length}</p>
                        </div>
                        <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                            <FileText className="w-6 h-6 text-blue-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <Activity className="w-4 h-4 text-blue-400" />
                        <span className="text-gray-400">Total logs processed</span>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">MITRE Tactics</p>
                            <p className="text-3xl font-bold mt-1">{uniqueTactics}</p>
                        </div>
                        <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                            <Target className="w-6 h-6 text-purple-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <span className="text-gray-400">Unique tactics detected</span>
                    </div>
                </div>

                <div className="stat-card">
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-gray-400 text-sm">Processed Files</p>
                            <p className="text-3xl font-bold mt-1">{files.filter(f => f.status === 'processed').length}</p>
                        </div>
                        <div className="w-12 h-12 bg-teal-500/20 rounded-xl flex items-center justify-center">
                            <Activity className="w-6 h-6 text-teal-400" />
                        </div>
                    </div>
                    <div className="mt-4 flex items-center gap-2 text-sm">
                        <span className="text-gray-400">Ready for review</span>
                    </div>
                </div>
            </div>

            {/* Charts Grid - Row 1 */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Incident Timeline */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="font-semibold">Incident Timeline</h3>
                    </div>
                    <div className="card-body">
                        {timelineData.length > 0 ? (
                            <ResponsiveContainer width="100%" height={300}>
                                <LineChart data={timelineData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                    <XAxis dataKey="date" stroke="#64748b" />
                                    <YAxis stroke="#64748b" allowDecimals={false} />
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#1e293b',
                                            border: '1px solid rgba(255,255,255,0.1)',
                                            borderRadius: '8px'
                                        }}
                                    />
                                    <Line
                                        type="monotone"
                                        dataKey="incidents"
                                        stroke="#ef4444"
                                        strokeWidth={2}
                                        dot={{ fill: '#ef4444' }}
                                    />
                                </LineChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="h-[300px] flex items-center justify-center text-gray-500">
                                No incident data available
                            </div>
                        )}
                    </div>
                </div>

                {/* Priority Distribution - Pie Chart */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="font-semibold">Incidents by Priority</h3>
                    </div>
                    <div className="card-body">
                        <ResponsiveContainer width="100%" height={300}>
                            <PieChart>
                                <Pie
                                    data={priorityData.length ? priorityData : [{ name: 'No Data', value: 1, color: '#6b7280' }]}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={100}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {(priorityData.length ? priorityData : [{ color: '#6b7280' }]).map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: '#1e293b',
                                        border: '1px solid rgba(255,255,255,0.1)',
                                        borderRadius: '8px'
                                    }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                        <div className="flex justify-center gap-6 mt-4 flex-wrap">
                            {priorityData.map((item) => (
                                <div key={item.name} className="flex items-center gap-2">
                                    <div
                                        className="w-3 h-3 rounded-full"
                                        style={{ backgroundColor: item.color }}
                                    />
                                    <span className="text-sm text-gray-400">{item.name}: {item.value}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>

            {/* Charts Grid - Row 2: Severity & MITRE */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Severity Breakdown - Bar Chart */}
                <div className="card">
                    <div className="card-header">
                        <h3 className="font-semibold">Severity Breakdown</h3>
                    </div>
                    <div className="card-body">
                        {severityData.length > 0 ? (
                            <ResponsiveContainer width="100%" height={300}>
                                <BarChart data={severityData} layout="vertical">
                                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
                                    <XAxis type="number" stroke="#64748b" />
                                    <YAxis type="category" dataKey="name" stroke="#64748b" width={80} />
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#1e293b',
                                            border: '1px solid rgba(255,255,255,0.1)',
                                            borderRadius: '8px'
                                        }}
                                    />
                                    <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                                        {severityData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="h-[300px] flex items-center justify-center text-gray-500">
                                No severity data available
                            </div>
                        )}
                    </div>
                </div>

                {/* MITRE Tactics Distribution */}
                <div className="card">
                    <div className="card-header flex justify-between items-center">
                        <h3 className="font-semibold">MITRE ATT&CK Tactics</h3>
                        <Link to="/mitre" className="text-sm text-primary-400 hover:text-primary-300">
                            View Details →
                        </Link>
                    </div>
                    <div className="card-body">
                        {mitreData.length > 0 ? (
                            <ResponsiveContainer width="100%" height={300}>
                                <BarChart data={mitreData}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                    <XAxis
                                        dataKey="name"
                                        stroke="#64748b"
                                        tick={{ fontSize: 10 }}
                                        angle={-45}
                                        textAnchor="end"
                                        height={80}
                                    />
                                    <YAxis stroke="#64748b" allowDecimals={false} />
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#1e293b',
                                            border: '1px solid rgba(255,255,255,0.1)',
                                            borderRadius: '8px'
                                        }}
                                    />
                                    <Bar dataKey="value" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="h-[300px] flex flex-col items-center justify-center text-gray-500">
                                <Target className="w-12 h-12 mb-4 opacity-20" />
                                <p>No MITRE tactics detected yet</p>
                                <p className="text-sm mt-1">Run analysis to detect threat tactics</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Quick Actions */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">Quick Actions</h3>
                </div>
                <div className="card-body">
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <Link
                            to="/upload"
                            className="flex items-center gap-4 p-4 bg-surface-dark rounded-lg border border-white/10 hover:border-primary-500/50 transition-all duration-200 group"
                        >
                            <div className="w-12 h-12 bg-primary-500/20 rounded-xl flex items-center justify-center group-hover:bg-primary-500/30 transition-colors">
                                <Upload className="w-6 h-6 text-primary-400" />
                            </div>
                            <div>
                                <p className="font-medium">Upload Log File</p>
                                <p className="text-sm text-gray-400">Analyze new CSV logs</p>
                            </div>
                        </Link>

                        <Link
                            to="/analysis"
                            className="flex items-center gap-4 p-4 bg-surface-dark rounded-lg border border-white/10 hover:border-blue-500/50 transition-all duration-200 group"
                        >
                            <div className="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center group-hover:bg-blue-500/30 transition-colors">
                                <Activity className="w-6 h-6 text-blue-400" />
                            </div>
                            <div>
                                <p className="font-medium">Run Analysis</p>
                                <p className="text-sm text-gray-400">AI threat detection</p>
                            </div>
                        </Link>

                        <Link
                            to="/incidents"
                            className="flex items-center gap-4 p-4 bg-surface-dark rounded-lg border border-white/10 hover:border-orange-500/50 transition-all duration-200 group"
                        >
                            <div className="w-12 h-12 bg-orange-500/20 rounded-xl flex items-center justify-center group-hover:bg-orange-500/30 transition-colors">
                                <AlertTriangle className="w-6 h-6 text-orange-400" />
                            </div>
                            <div>
                                <p className="font-medium">View Incidents</p>
                                <p className="text-sm text-gray-400">Review threat detections</p>
                            </div>
                        </Link>

                        <Link
                            to="/mitre"
                            className="flex items-center gap-4 p-4 bg-surface-dark rounded-lg border border-white/10 hover:border-purple-500/50 transition-all duration-200 group"
                        >
                            <div className="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center group-hover:bg-purple-500/30 transition-colors">
                                <Target className="w-6 h-6 text-purple-400" />
                            </div>
                            <div>
                                <p className="font-medium">MITRE Mapping</p>
                                <p className="text-sm text-gray-400">ATT&CK framework view</p>
                            </div>
                        </Link>
                    </div>
                </div>
            </div>
        </div>
    );
}
