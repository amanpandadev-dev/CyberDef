import { useMemo, useState, type ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
    Shield,
    Upload,
    AlertTriangle,
    BarChart3,
    Settings,
    Activity,
    Split,
    Target,
    CheckCircle2,
    Loader2,
    LogOut,
} from 'lucide-react';
import { useAnalysis } from '../context/AnalysisContext';
import { useAuth } from '../context/AuthContext';
import HoverHint from './HoverHint';

interface LayoutProps {
    children: ReactNode;
}

const navItems = [
    { path: '/', label: 'Dashboard', icon: BarChart3 },
    { path: '/upload', label: 'File Upload', icon: Upload },
    { path: '/analysis', label: 'Analysis', icon: Activity },
    { path: '/log-flow', label: 'Log Flow', icon: Split },
    { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
    { path: '/mitre', label: 'MITRE', icon: Target },
    { path: '/validation', label: 'Validation', icon: CheckCircle2 },
];

export default function Layout({ children }: LayoutProps) {
    const location = useLocation();
    const { state: analysisState, isAnalyzing } = useAnalysis();
    const { username, displayName, logout } = useAuth();
    const [isLoggingOut, setIsLoggingOut] = useState(false);

    const activeItem = useMemo(
        () => navItems.find((item) => location.pathname === item.path),
        [location.pathname],
    );

    const handleLogout = async () => {
        setIsLoggingOut(true);
        await logout();
    };

    return (
        <div className="min-h-screen">
            <HoverHint />
            <header className="sticky top-0 z-40 h-[60px] border-b border-slate-200 bg-white/90 backdrop-blur-md">
                <div className="mx-auto flex h-full max-w-[1400px] items-center justify-between gap-3 px-4 sm:px-6">
                    <Link
                        to="/"
                        className="help-hover flex items-center gap-2 rounded-xl px-2 py-1.5 transition-all"
                        data-help="Go to your planning dashboard overview"
                    >
                        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary-600 text-white shadow-md shadow-primary-600/25">
                            <Shield className="h-4 w-4" />
                        </div>
                        <div className="hidden sm:block">
                            <p className="text-sm font-bold text-slate-900">Cyberdef 1.0</p>
                            <p className="text-[11px] text-slate-500">AI Planning Workspace</p>
                        </div>
                    </Link>

                    <div className="flex-1" />

                    <div className="flex items-center gap-2">
                        <Link
                            to="/settings"
                            className="help-hover rounded-lg p-2 text-slate-500 transition-all hover:bg-slate-100"
                            data-help="Open system configuration"
                        >
                            <Settings className="h-4 w-4" />
                        </Link>
                        <div className="hidden max-w-[220px] truncate text-xs text-slate-500 sm:block">
                            {displayName ? `Hi ${displayName}` : username ? `Hi ${username}` : ''}
                        </div>
                        <button
                            type="button"
                            className="rounded-lg border border-slate-200 px-2.5 py-2 text-slate-600 transition-all hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                            onClick={() => {
                                void handleLogout();
                            }}
                            disabled={isLoggingOut}
                        >
                            <span className="flex items-center gap-1.5 text-xs font-semibold">
                                <LogOut className="h-3.5 w-3.5" />
                                {isLoggingOut ? 'Signing out...' : 'Logout'}
                            </span>
                        </button>
                    </div>
                </div>
            </header>

            {isAnalyzing && (
                <div className="border-b border-indigo-100 bg-indigo-50/80">
                    <div className="mx-auto flex max-w-[1400px] items-center gap-3 px-4 py-2 text-sm sm:px-6">
                        <Loader2 className="h-4 w-4 animate-spin text-primary-600" />
                        <span className="font-semibold text-primary-700">Analyzing:</span>
                        <span className="truncate text-primary-700">{analysisState.fileName || 'Selected file'}</span>
                        <div className="ml-auto h-1.5 w-40 overflow-hidden rounded-full bg-indigo-100">
                            <div
                                className="h-full rounded-full bg-primary-600 transition-all duration-300"
                                style={{ width: `${analysisState.progress.percent}%` }}
                            />
                        </div>
                    </div>
                </div>
            )}

            <main className="px-4 py-5 sm:px-6">
                <div className="mx-auto flex w-full max-w-[1700px] gap-6">
                    <aside className="hidden lg:block w-[300px] flex-shrink-0">
                        <div
                            className="sticky top-[72px] h-[calc(100vh-88px)] overflow-hidden rounded-2xl border p-3"
                            style={{
                                background: 'var(--bg-panel)',
                                borderColor: 'var(--border-soft)',
                                boxShadow: 'var(--shadow-soft)',
                            }}
                        >
                            <p className="px-3 py-2 text-xs font-bold uppercase tracking-[0.14em] text-slate-500">
                                Navigation
                            </p>
                            <nav className="mt-1 h-[calc(100%-42px)] space-y-1 overflow-y-auto pr-1">
                                {navItems.map((item) => {
                                    const Icon = item.icon;
                                    const isActive = location.pathname === item.path;
                                    return (
                                        <Link
                                            key={item.path}
                                            to={item.path}
                                            className={`help-hover flex items-center gap-2 rounded-lg px-3 py-2.5 text-base font-semibold transition-all duration-200 ${
                                                isActive
                                                    ? 'bg-primary-600 text-white shadow-md shadow-primary-600/20'
                                                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                                            }`}
                                            data-help={`Navigate to ${item.label}`}
                                        >
                                            <Icon className="h-4 w-4" />
                                            <span>{item.label}</span>
                                        </Link>
                                    );
                                })}
                            </nav>
                        </div>
                    </aside>

                    <div className="min-w-0 flex-1">
                        <div className="mb-4 flex items-center gap-2 text-sm text-slate-500">
                            <span className="font-semibold text-slate-700">Current:</span>
                            <span>{activeItem?.label ?? 'Workspace'}</span>
                        </div>
                        <div className="space-y-6">{children}</div>
                    </div>
                </div>
            </main>
        </div>
    );
}
