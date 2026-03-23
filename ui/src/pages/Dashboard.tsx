import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
    Bar,
    BarChart,
    CartesianGrid,
    Cell,
    Line,
    LineChart,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from 'recharts';
import { getFiles, getIncidents, healthCheck, listGeneratedReports, type GeneratedReport } from '../api';
import { formatISTDate, formatISTDateTime, toISTDateKey } from '../utils/datetime';

interface FileData {
    file_id: string;
    original_filename: string;
    filename?: string;
    status?: string;
    uploaded_at: string;
    row_count?: number | null;
}

interface IncidentData {
    incident_id: string;
    title: string;
    status: string;
    priority: string;
    first_seen: string;
    confidence: number;
    primary_tactic?: string | null;
    mitre_tactic?: string | null;
    mitre_technique?: string | null;
    attack_name?: string | null;
    file_ids?: string[];
}

const PRIORITY_COLORS: Record<string, string> = {
    critical: '#dc2626',
    high: '#ea580c',
    medium: '#f59e0b',
    low: '#0ca678',
    informational: '#3b82f6',
};

const normalizeValue = (value?: string | null) => (value || '').trim().toLowerCase();

const toStem = (name?: string) =>
    normalizeValue(name)
        .replace(/\.[^./\\]+$/, '')
        .replace(/\s+/g, '_');

export default function Dashboard() {
    const [health, setHealth] = useState<any>(null);
    const [files, setFiles] = useState<FileData[]>([]);
    const [incidents, setIncidents] = useState<IncidentData[]>([]);
    const [reports, setReports] = useState<GeneratedReport[]>([]);
    const [activeTab, setActiveTab] = useState('all');
    const [openTabs, setOpenTabs] = useState<string[]>([]);
    const [fileSelectorValue, setFileSelectorValue] = useState('');

    useEffect(() => {
        const fetchData = async () => {
            const [healthData, fileData, incidentData, reportData] = await Promise.all([
                healthCheck().catch(() => null),
                getFiles().catch(() => []),
                getIncidents().catch(() => []),
                listGeneratedReports().catch(() => []),
            ]);
            setHealth(healthData);
            setFiles(fileData || []);
            setIncidents(incidentData || []);
            setReports(reportData || []);
        };

        fetchData();
        const interval = setInterval(fetchData, 30000);
        return () => clearInterval(interval);
    }, []);

    useEffect(() => {
        if (activeTab === 'all') return;
        if (!files.some((file) => file.file_id === activeTab)) setActiveTab('all');
    }, [activeTab, files]);

    const filteredIncidents = useMemo(() => {
        if (activeTab === 'all') return incidents;
        return incidents.filter((incident) => (incident.file_ids || []).map(String).includes(activeTab));
    }, [activeTab, incidents]);

    const stats = useMemo(() => {
        return filteredIncidents.reduce(
            (acc, incident) => {
                acc.total += 1;
                if (incident.priority in acc) acc[incident.priority as keyof typeof acc] += 1;
                return acc;
            },
            { total: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        );
    }, [filteredIncidents]);

    const priorityData = useMemo(() => {
        return Object.entries(stats)
            .filter(([key, value]) => key !== 'total' && value > 0)
            .map(([key, value]) => ({
                name: key.charAt(0).toUpperCase() + key.slice(1),
                value,
                color: PRIORITY_COLORS[key] || '#94a3b8',
            }));
    }, [stats]);

    const timelineData = useMemo(() => {
        const grouped: Record<string, { count: number; sortTs: number }> = {};
        filteredIncidents.forEach((incident) => {
            const date = new Date(incident.first_seen);
            const key = toISTDateKey(date);
            if (!grouped[key]) {
                grouped[key] = { count: 0, sortTs: date.getTime() };
            }
            grouped[key].count += 1;
        });
        return Object.entries(grouped)
            .map(([date, bucket]) => ({ date, incidents: bucket.count, sortTs: bucket.sortTs }))
            .sort((a, b) => a.sortTs - b.sortTs);
    }, [filteredIncidents]);

    const tacticData = useMemo(() => {
        const grouped: Record<string, number> = {};
        filteredIncidents.forEach((incident) => {
            const tactic = incident.mitre_tactic || incident.primary_tactic;
            if (!tactic) return;
            grouped[tactic] = (grouped[tactic] || 0) + 1;
        });
        return Object.entries(grouped)
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 8);
    }, [filteredIncidents]);

    const mitreIncidentRows = useMemo(
        () =>
            filteredIncidents
                .filter((incident) => incident.mitre_tactic || incident.primary_tactic || incident.mitre_technique)
                .slice(0, 8),
        [filteredIncidents],
    );

    const sortedFiles = useMemo(
        () =>
            [...files].sort(
                (a, b) => new Date(b.uploaded_at).getTime() - new Date(a.uploaded_at).getTime(),
            ),
        [files],
    );

    const fileTimelineData = useMemo(() => {
        const grouped: Record<string, { count: number; sortTs: number }> = {};
        sortedFiles.forEach((file) => {
            const date = new Date(file.uploaded_at);
            const key = formatISTDate(date);
            if (!grouped[key]) {
                grouped[key] = { count: 0, sortTs: date.getTime() };
            }
            grouped[key].count += 1;
        });

        return Object.entries(grouped)
            .map(([date, bucket]) => ({ date, files: bucket.count, sortTs: bucket.sortTs }))
            .sort((a, b) => a.sortTs - b.sortTs);
    }, [sortedFiles]);

    const fileReportStatus = useMemo(() => {
        const reportIndex = reports.map((report) => ({
            fileId: normalizeValue(report.file_id),
            reportName: normalizeValue(report.report_name),
            reportPath: normalizeValue(report.report_path),
        }));

        const statusMap: Record<string, boolean> = {};
        files.forEach((file) => {
            const normalizedFileId = normalizeValue(file.file_id);
            const fileStem = toStem(file.filename || file.original_filename);
            const isProcessed = normalizeValue(file.status) === 'processed';

            statusMap[file.file_id] = isProcessed || reportIndex.some((report) => {
                if (report.fileId && report.fileId === normalizedFileId) return true;
                if (normalizedFileId && (report.reportName.includes(normalizedFileId) || report.reportPath.includes(normalizedFileId))) {
                    return true;
                }
                if (fileStem && report.reportName.includes(fileStem)) return true;
                return false;
            });
        });

        return statusMap;
    }, [files, reports]);

    const readyReportCount = useMemo(
        () => files.filter((file) => fileReportStatus[file.file_id]).length,
        [fileReportStatus, files],
    );

    const openTabFiles = useMemo(
        () => openTabs.map((fileId) => sortedFiles.find((file) => file.file_id === fileId)).filter(Boolean) as FileData[],
        [openTabs, sortedFiles],
    );

    const openLogeventTab = (fileId: string) => {
        if (!fileId) return;
        setOpenTabs((prev) => (prev.includes(fileId) ? prev : [...prev, fileId]));
        setActiveTab(fileId);
        setFileSelectorValue('');
    };

    const closeLogeventTab = (fileId: string) => {
        setOpenTabs((prev) => {
            const next = prev.filter((id) => id !== fileId);
            if (activeTab === fileId) {
                setActiveTab(next.length ? next[next.length - 1] : 'all');
            }
            return next;
        });
    };

    useEffect(() => {
        setOpenTabs((prev) => prev.filter((tabId) => files.some((file) => file.file_id === tabId)));
    }, [files]);

    return (
        <div className="space-y-6 pb-10">
            <div className="card glass-panel">
                <div className="card-body flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                    <div>
                        <h1 className="text-3xl font-extrabold">AI Planning Dashboard</h1>
                        <p className="mt-1 text-sm text-slate-600">
                            Linear style dashboard with per-logevent tabs and report integration.
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        <Link to="/analysis" className="btn btn-primary pulse-save help-hover" data-help="Open analysis and markdown reports">
                            Open Analysis
                        </Link>
                    </div>
                </div>
            </div>

            <div className="card">
                <div className="card-body space-y-3">
                    <div className="flex items-center justify-between gap-3">
                        <p className="text-xs font-bold uppercase tracking-[0.14em] text-slate-500">Logevent Tabs</p>
                        <span className={`rounded-full px-3 py-1 text-xs font-semibold ${health?.status === 'healthy' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                            {health?.status === 'healthy' ? 'System Healthy' : 'System Degraded'}
                        </span>
                    </div>
                    <div className="flex flex-col gap-3">
                        <div className="flex flex-wrap items-center gap-2">
                            <button
                                onClick={() => setActiveTab('all')}
                                className={`help-hover min-w-max rounded-lg border px-4 py-2 text-sm font-semibold transition-all duration-200 ${activeTab === 'all' ? 'border-primary-600 bg-primary-600 text-white' : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'}`}
                                data-help="View dashboard stats for all logevents"
                            >
                                All Logevents
                            </button>
                            <select
                                value={fileSelectorValue}
                                onChange={(event) => {
                                    const fileId = event.target.value;
                                    setFileSelectorValue(fileId);
                                    if (fileId) openLogeventTab(fileId);
                                }}
                                className="help-hover rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 transition-all duration-200"
                                data-help="Open a logevent as a closable tab"
                            >
                                <option value="">Open Log File Tab...</option>
                                {sortedFiles.map((file) => (
                                    <option key={file.file_id} value={file.file_id}>
                                        {(file.filename || file.original_filename) + ' | ' + formatISTDateTime(file.uploaded_at)}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {openTabFiles.map((file) => (
                                <div
                                    key={file.file_id}
                                    className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-semibold ${
                                        activeTab === file.file_id
                                            ? 'border-primary-600 bg-primary-50 text-primary-700'
                                            : 'border-slate-200 bg-white text-slate-700'
                                    }`}
                                >
                                    <button
                                        onClick={() => setActiveTab(file.file_id)}
                                        className="help-hover"
                                        data-help={`Switch to ${(file.filename || file.original_filename)}`}
                                    >
                                        {file.filename || file.original_filename}
                                    </button>
                                    <button
                                        onClick={() => closeLogeventTab(file.file_id)}
                                        className="help-hover rounded-full px-1 text-red-600 transition-colors hover:bg-red-50"
                                        data-help="Close this logevent tab"
                                        aria-label="Close logevent tab"
                                    >
                                        x
                                    </button>
                                </div>
                            ))}
                            {openTabFiles.length === 0 && (
                                <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 px-3 py-2 text-xs text-slate-500">
                                    No specific tabs open. Use the dropdown to open a log file tab.
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-5">
                <div className="stat-card"><p className="text-xs text-slate-500">Incidents</p><p className="text-3xl font-extrabold text-slate-900">{stats.total}</p></div>
                <div className="stat-card"><p className="text-xs text-slate-500">Critical</p><p className="text-3xl font-extrabold text-red-600">{stats.critical}</p></div>
                <div className="stat-card"><p className="text-xs text-slate-500">High</p><p className="text-3xl font-extrabold text-orange-600">{stats.high}</p></div>
                <div className="stat-card"><p className="text-xs text-slate-500">Reports Ready</p><p className="text-3xl font-extrabold text-indigo-600">{readyReportCount}</p></div>
                <div className="stat-card"><p className="text-xs text-slate-500">Files</p><p className="text-3xl font-extrabold text-slate-900">{files.length}</p></div>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <div className="card">
                    <div className="card-header">Incident Timeline (IST)</div>
                    <div className="card-body">
                        <ResponsiveContainer width="100%" height={260}>
                            <LineChart data={timelineData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#d8dbe8" />
                                <XAxis dataKey="date" stroke="#64748b" />
                                <YAxis allowDecimals={false} stroke="#64748b" />
                                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #d8dbe8', borderRadius: '10px' }} />
                                <Line type="monotone" dataKey="incidents" stroke="#4f46e5" strokeWidth={2.4} dot={{ fill: '#4f46e5' }} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">Priority Distribution</div>
                    <div className="card-body">
                        <ResponsiveContainer width="100%" height={260}>
                            <PieChart>
                                <Pie data={priorityData.length ? priorityData : [{ name: 'No Data', value: 1, color: '#cbd5e1' }]} cx="50%" cy="50%" innerRadius={58} outerRadius={92} dataKey="value">
                                    {(priorityData.length ? priorityData : [{ name: 'No Data', value: 1, color: '#cbd5e1' }]).map((entry, idx) => (
                                        <Cell key={`${entry.name}-${idx}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #d8dbe8', borderRadius: '10px' }} />
                            </PieChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <div className="card">
                    <div className="card-header">MITRE Tactic Coverage</div>
                    <div className="card-body space-y-4">
                        <ResponsiveContainer width="100%" height={280}>
                            <BarChart data={tacticData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#d8dbe8" />
                                <XAxis dataKey="name" tick={{ fontSize: 10 }} angle={-40} textAnchor="end" height={80} stroke="#64748b" />
                                <YAxis allowDecimals={false} stroke="#64748b" />
                                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #d8dbe8', borderRadius: '10px' }} />
                                <Bar dataKey="value" fill="#0ca678" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                        <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                            <p className="mb-2 text-xs font-bold uppercase tracking-[0.12em] text-slate-500">Per-Incident MITRE Mapping</p>
                            <div className="space-y-2">
                                {mitreIncidentRows.length === 0 && (
                                    <p className="text-xs text-slate-500">No mapped MITRE techniques available for this tab yet.</p>
                                )}
                                {mitreIncidentRows.map((incident) => (
                                    <div key={incident.incident_id} className="rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs">
                                        <p className="font-semibold text-slate-800">{incident.attack_name || incident.title}</p>
                                        <p className="mt-1 text-slate-600">
                                            Tactic: {incident.mitre_tactic || incident.primary_tactic || 'N/A'} | Technique: {incident.mitre_technique || 'N/A'}
                                        </p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">Log File Timestamp Timeline (IST)</div>
                    <div className="card-body">
                        <ResponsiveContainer width="100%" height={280}>
                            <LineChart data={fileTimelineData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#d8dbe8" />
                                <XAxis dataKey="date" stroke="#64748b" />
                                <YAxis allowDecimals={false} stroke="#64748b" />
                                <Tooltip contentStyle={{ backgroundColor: '#fff', border: '1px solid #d8dbe8', borderRadius: '10px' }} />
                                <Line type="monotone" dataKey="files" stroke="#0ca678" strokeWidth={2.4} dot={{ fill: '#0ca678' }} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
                <div className="card">
                    <div className="card-header">Logevent List</div>
                    <div className="card-body space-y-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">
                            Latest log files (dd/mm/yyyy, IST)
                        </p>
                        {sortedFiles.slice(0, 8).map((file) => {
                            const hasReport = fileReportStatus[file.file_id];
                            const normalizedStatus = hasReport ? 'processed' : normalizeValue(file.status) || 'pending';
                            const statusColor =
                                normalizedStatus === 'processed'
                                    ? 'bg-emerald-100 text-emerald-700'
                                    : normalizedStatus === 'failed'
                                        ? 'bg-red-100 text-red-700'
                                        : 'bg-amber-100 text-amber-700';
                            return (
                                <button
                                    key={file.file_id}
                                    onClick={() => setActiveTab(file.file_id)}
                                    className="help-hover w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-left transition-all duration-200 hover:bg-slate-50"
                                    data-help="Click to open this logevent as a full dashboard tab"
                                >
                                    <div className="flex flex-wrap items-center justify-between gap-3">
                                        <div>
                                            <p className="font-semibold text-slate-900">{file.filename || file.original_filename}</p>
                                            <p className="text-xs text-slate-500">{formatISTDateTime(file.uploaded_at)}</p>
                                        </div>
                                        <div className="flex items-center gap-2 text-xs">
                                            <span className={`rounded-full px-3 py-1 font-semibold ${statusColor}`}>{normalizedStatus.toUpperCase()}</span>
                                            <span className={`rounded-full px-3 py-1 font-semibold ${hasReport ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                                                {hasReport ? 'REPORT READY' : 'REPORT PENDING'}
                                            </span>
                                        </div>
                                    </div>
                                </button>
                            );
                        })}
                        {sortedFiles.length > 8 && (
                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-500">
                                Showing 8 of {sortedFiles.length} files. Use the "Open Log File Tab" dropdown above to access all files.
                            </div>
                        )}
                        {files.length === 0 && (
                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-500">
                                No logevents found. Upload a CSV file to start.
                            </div>
                        )}
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">Current Tab Feed</div>
                    <div className="card-body space-y-3">
                        {filteredIncidents.length === 0 && <div className="text-sm text-slate-500">No incidents in the selected tab yet.</div>}
                        {filteredIncidents.slice(0, 8).map((incident) => (
                            <Link
                                key={incident.incident_id}
                                to={`/incidents/${incident.incident_id}`}
                                className="help-hover block rounded-xl border border-slate-200 bg-white px-4 py-3 transition-all duration-200 hover:-translate-y-1 hover:shadow-md"
                                data-help="Open full incident detail and recommendations"
                            >
                                <p className="font-semibold text-slate-900">{incident.title}</p>
                                <p className="mt-1 text-xs text-slate-500">{formatISTDateTime(incident.first_seen)}</p>
                            </Link>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

