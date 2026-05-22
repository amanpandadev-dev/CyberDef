import { Link } from 'react-router-dom';
import { Activity, AlertTriangle, FileText, Upload } from 'lucide-react';

const quickActions = [
    {
        to: '/upload',
        title: 'Upload File',
        description: 'Add CSV logs and queue them for processing',
        icon: Upload,
        help: 'Upload a CSV file so the analysis pipeline can run',
    },
    {
        to: '/analysis',
        title: 'Run Analysis',
        description: 'Execute AI pipeline and generate markdown report',
        icon: Activity,
        help: 'Run analysis for uploaded files and read report output',
    },
    {
        to: '/incidents',
        title: 'View Incidents',
        description: 'Review findings, confidence, and recommendations',
        icon: AlertTriangle,
        help: 'Navigate to incidents and triage suspicious activity',
    },
    {
        to: '/rollups',
        title: 'Rollup Trends',
        description: 'See long-horizon actor behavior and risk',
        icon: FileText,
        help: 'Open rollup analytics for cross-file threat patterns',
    },
];

export default function QuickActions() {
    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold">Quick Actions</h1>
                <p className="text-gray-400 mt-1">Fast shortcuts for common workflows</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {quickActions.map((action) => {
                    const Icon = action.icon;
                    return (
                        <Link
                            key={action.to}
                            to={action.to}
                            className="help-hover card p-5 transition-all duration-200 hover:-translate-y-1"
                            data-help={action.help}
                        >
                            <div className="w-11 h-11 rounded-lg bg-primary-500/20 text-primary-300 flex items-center justify-center mb-3">
                                <Icon className="w-5 h-5" />
                            </div>
                            <p className="font-semibold text-white">{action.title}</p>
                            <p className="text-sm text-gray-400 mt-1">{action.description}</p>
                        </Link>
                    );
                })}
            </div>
        </div>
    );
}
