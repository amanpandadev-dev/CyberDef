import { useState } from 'react';
import { Settings as SettingsIcon, Trash2, AlertTriangle, CheckCircle2, Loader2, Database, FileText, FolderOpen, Shield } from 'lucide-react';

const API_BASE = 'http://localhost:8000/api/v1';

export default function SettingsPage() {
    const [clearing, setClearing] = useState(false);
    const [clearResult, setClearResult] = useState<{ status: string; cleared: string[] } | null>(null);
    const [showConfirm, setShowConfirm] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleClearAll = async () => {
        setClearing(true);
        setError(null);
        setClearResult(null);
        try {
            const res = await fetch(`${API_BASE}/system/clear-all`, { method: 'DELETE' });
            if (!res.ok) throw new Error(`Failed: ${res.statusText}`);
            const data = await res.json();
            setClearResult(data);
        } catch (e: any) {
            setError(e.message || 'Failed to clear data');
        } finally {
            setClearing(false);
            setShowConfirm(false);
        }
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div>
                <h1 className="text-3xl font-bold gradient-text flex items-center gap-3">
                    <SettingsIcon className="w-8 h-8" />
                    Settings
                </h1>
                <p className="text-gray-400 mt-2">System configuration and data management</p>
            </div>

            {/* System Info Card */}
            <div className="bg-surface-dark rounded-xl border border-white/10 p-6">
                <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary-400" />
                    System Information
                </h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-surface rounded-lg p-4">
                        <p className="text-xs text-gray-500 uppercase tracking-wider">Engine</p>
                        <p className="text-lg font-semibold text-white mt-1">CyberDef 1.0</p>
                    </div>
                    <div className="bg-surface rounded-lg p-4">
                        <p className="text-xs text-gray-500 uppercase tracking-wider">Detection Rules</p>
                        <p className="text-lg font-semibold text-primary-400 mt-1">60 Rules</p>
                    </div>
                    <div className="bg-surface rounded-lg p-4">
                        <p className="text-xs text-gray-500 uppercase tracking-wider">Analysis Tiers</p>
                        <p className="text-lg font-semibold text-emerald-400 mt-1">3-Tier Pipeline</p>
                    </div>
                    <div className="bg-surface rounded-lg p-4">
                        <p className="text-xs text-gray-500 uppercase tracking-wider">AI Model</p>
                        <p className="text-lg font-semibold text-purple-400 mt-1">Ollama Local</p>
                    </div>
                </div>
            </div>

            {/* Clear All Data Card */}
            <div className="bg-surface-dark rounded-xl border border-red-500/20 p-6">
                <h2 className="text-lg font-semibold text-white mb-2 flex items-center gap-2">
                    <Trash2 className="w-5 h-5 text-red-400" />
                    Clear All Data
                </h2>
                <p className="text-gray-400 text-sm mb-4">
                    Remove all analysis data, incidents, reports, and uploaded files for a fresh start.
                    This action cannot be undone.
                </p>

                {/* What gets cleared */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
                    {[
                        { icon: Database, label: 'Database Tables', desc: 'Files, incidents, events' },
                        { icon: FolderOpen, label: 'Raw Files', desc: 'Uploaded log files' },
                        { icon: FileText, label: 'Processed Data', desc: 'Cache, state, rollups' },
                        { icon: FileText, label: 'Reports', desc: 'Analysis reports' },
                    ].map((item, i) => (
                        <div key={i} className="bg-surface rounded-lg p-3 border border-white/5">
                            <item.icon className="w-4 h-4 text-red-400 mb-1" />
                            <p className="text-sm font-medium text-white">{item.label}</p>
                            <p className="text-xs text-gray-500">{item.desc}</p>
                        </div>
                    ))}
                </div>

                {/* Clear button / Confirmation */}
                {!showConfirm ? (
                    <button
                        onClick={() => setShowConfirm(true)}
                        disabled={clearing}
                        className="px-6 py-3 bg-red-600/20 hover:bg-red-600/40 border border-red-500/30 text-red-400 
                                   rounded-lg font-medium transition-all duration-200 flex items-center gap-2"
                    >
                        <Trash2 className="w-4 h-4" />
                        Clear All Data
                    </button>
                ) : (
                    <div className="flex items-center gap-4 p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
                        <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" />
                        <div className="flex-1">
                            <p className="text-red-300 font-medium">Are you sure? This will delete everything.</p>
                            <p className="text-red-400/60 text-sm mt-1">All files, incidents, reports, and cached data will be permanently removed.</p>
                        </div>
                        <div className="flex gap-2 flex-shrink-0">
                            <button
                                onClick={() => setShowConfirm(false)}
                                className="px-4 py-2 bg-surface hover:bg-white/10 text-gray-400 rounded-lg transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleClearAll}
                                disabled={clearing}
                                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium 
                                           transition-colors flex items-center gap-2 disabled:opacity-50"
                            >
                                {clearing ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Clearing...
                                    </>
                                ) : (
                                    <>
                                        <Trash2 className="w-4 h-4" />
                                        Yes, Clear Everything
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                )}

                {/* Success Result */}
                {clearResult && (
                    <div className="mt-4 p-4 bg-emerald-900/20 border border-emerald-500/30 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                            <p className="text-emerald-300 font-medium">{clearResult.status === 'success' ? 'All data cleared successfully!' : 'Partial clear'}</p>
                        </div>
                        <div className="flex flex-wrap gap-2 mt-2">
                            {clearResult.cleared.map((item, i) => (
                                <span key={i} className="px-2 py-1 bg-emerald-800/30 text-emerald-400 text-xs rounded-full">
                                    ✓ {item.replace(/_/g, ' ')}
                                </span>
                            ))}
                        </div>
                    </div>
                )}

                {/* Error */}
                {error && (
                    <div className="mt-4 p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
                        <p className="text-red-400">Error: {error}</p>
                    </div>
                )}
            </div>
        </div>
    );
}
