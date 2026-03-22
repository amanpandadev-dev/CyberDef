import { useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Shield,
    Upload,
    AlertTriangle,
    BarChart3,
    Settings,
    Menu,
    X,
    Activity,
    Split,
    Target,
    CheckCircle2,
    Loader2,
    TrendingUp
} from 'lucide-react';
import { useAnalysis } from '../context/AnalysisContext';

interface LayoutProps {
    children: ReactNode;
}

const navItems = [
    { path: '/', label: 'Dashboard', icon: BarChart3 },
    { path: '/upload', label: 'File Upload', icon: Upload },
    { path: '/analysis', label: 'Analysis', icon: Activity },
    { path: '/pipeline', label: 'Pipeline', icon: Split },
    { path: '/rollups', label: 'Rollups', icon: TrendingUp },
    { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
    { path: '/mitre', label: 'MITRE Mapping', icon: Target },
    { path: '/validation', label: 'Validation', icon: CheckCircle2 },
];

export default function Layout({ children }: LayoutProps) {
    const location = useLocation();
    const [sidebarOpen, setSidebarOpen] = useState(true);
    const { state: analysisState, isAnalyzing } = useAnalysis();

    return (
        <div className="min-h-screen flex">
            {/* Sidebar */}
            <aside
                className={`${sidebarOpen ? 'w-64' : 'w-20'
                    } bg-surface-dark border-r border-white/10 transition-all duration-300 flex flex-col`}
            >
                {/* Logo */}
                <div className="h-16 flex items-center justify-between px-4 border-b border-white/10">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-purple-600 rounded-lg flex items-center justify-center">
                            <Shield className="w-6 h-6 text-white" />
                        </div>
                        {sidebarOpen && (
                            <div>
                                <h1 className="font-bold text-lg gradient-text">Cyberdef 1.0</h1>
                                <p className="text-xs text-gray-500">AI Threat Intelligence</p>
                            </div>
                        )}
                    </div>
                    <button
                        onClick={() => setSidebarOpen(!sidebarOpen)}
                        className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                    >
                        {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
                    </button>
                </div>

                {/* Analysis Indicator - Shows when analysis is running */}
                {isAnalyzing && (
                    <Link
                        to="/analysis"
                        className="mx-4 mt-4 p-3 bg-primary-600/20 border border-primary-500/30 rounded-lg hover:bg-primary-600/30 transition-colors"
                    >
                        <div className="flex items-center gap-3">
                            <Loader2 className="w-5 h-5 text-primary-400 animate-spin" />
                            {sidebarOpen && (
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium text-primary-300 truncate">
                                        Analyzing...
                                    </p>
                                    <p className="text-xs text-gray-400 truncate">
                                        {analysisState.fileName || 'File'}
                                    </p>
                                    <div className="mt-1 h-1 bg-surface-dark rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-primary-500 transition-all duration-300"
                                            style={{ width: `${analysisState.progress.percent}%` }}
                                        />
                                    </div>
                                </div>
                            )}
                        </div>
                    </Link>
                )}

                {/* Navigation */}
                <nav className="flex-1 p-4 space-y-2">
                    {navItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = location.pathname === item.path;

                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${isActive
                                    ? 'bg-primary-600 text-white shadow-lg shadow-primary-500/25'
                                    : 'text-gray-400 hover:text-white hover:bg-white/10'
                                    }`}
                            >
                                <Icon className="w-5 h-5 flex-shrink-0" />
                                {sidebarOpen && <span className="font-medium">{item.label}</span>}
                            </Link>
                        );
                    })}
                </nav>

                {/* Footer */}
                <div className="p-4 border-t border-white/10">
                    <Link
                        to="/settings"
                        className="flex items-center gap-3 px-4 py-3 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-all duration-200"
                    >
                        <Settings className="w-5 h-5" />
                        {sidebarOpen && <span className="font-medium">Settings</span>}
                    </Link>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 overflow-auto">
                <div className="p-8">
                    {children}
                </div>
            </main>
        </div>
    );
}

