import { useEffect, useState, useCallback } from 'react';
import {
    Play,
    FileText,
    CheckCircle,
    Loader2,
    AlertCircle,
    Database,
    Split,
    Brain,
    AlertTriangle,
    Clock,
    ArrowRight
} from 'lucide-react';
import { getFiles, analyzeFile } from '../api';

interface FileData {
    file_id: string;
    original_filename: string;
    filename: string;
    status: string;
    row_count: number | null;
    uploaded_at: string;
    events_created: number;
    parse_errors: number;
}

interface AnalysisResult {
    file_id: string;
    events_parsed: number;
    events_normalized: number;
    chunks_created: number;
    suspicious_chunks: number;
    ai_analyses: number;
    incidents_created: number;
    incident_ids: string[];
}

interface PipelineStep {
    id: string;
    name: string;
    icon: React.ComponentType<any>;
    status: 'pending' | 'running' | 'completed' | 'error';
    detail?: string;
}

export default function Analysis() {
    const [files, setFiles] = useState<FileData[]>([]);
    const [loading, setLoading] = useState(true);
    const [analyzing, setAnalyzing] = useState<string | null>(null);
    const [results, setResults] = useState<Record<string, AnalysisResult>>({});
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [progress, setProgress] = useState<Record<string, PipelineStep[]>>({});
    const [elapsedTime, setElapsedTime] = useState<Record<string, number>>({});

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                const data = await getFiles();
                setFiles(data);
            } catch (error) {
                console.error('Failed to fetch files:', error);
            } finally {
                setLoading(false);
            }
        };

        fetchFiles();
    }, []);

    // Timer effect for elapsed time
    useEffect(() => {
        let interval: ReturnType<typeof setInterval> | null = null;

        if (analyzing) {
            interval = setInterval(() => {
                setElapsedTime(prev => ({
                    ...prev,
                    [analyzing]: (prev[analyzing] || 0) + 1
                }));
            }, 1000);
        }

        return () => {
            if (interval) clearInterval(interval);
        };
    }, [analyzing]);

    const initializeProgress = useCallback((): PipelineStep[] => {
        return [
            { id: 'parse', name: 'Parsing CSV', icon: FileText, status: 'pending' },
            { id: 'normalize', name: 'Normalizing Events', icon: Database, status: 'pending' },
            { id: 'chunk', name: 'Creating Chunks', icon: Split, status: 'pending' },
            { id: 'ai', name: 'AI Analysis', icon: Brain, status: 'pending' },
            { id: 'incident', name: 'Creating Incidents', icon: AlertTriangle, status: 'pending' }
        ];
    }, []);

    const simulateProgress = useCallback((fileId: string) => {
        const steps = initializeProgress();
        setProgress(prev => ({ ...prev, [fileId]: steps }));

        // Simulate progress through stages (real progress would come from API)
        const delays = [500, 1500, 3000, 5000, 7000];

        delays.forEach((delay, index) => {
            setTimeout(() => {
                setProgress(prev => {
                    const currentSteps = [...(prev[fileId] || steps)];

                    // Mark current step as running
                    if (currentSteps[index]) {
                        currentSteps[index] = { ...currentSteps[index], status: 'running' };
                    }

                    // Mark previous step as completed
                    if (index > 0 && currentSteps[index - 1]) {
                        currentSteps[index - 1] = { ...currentSteps[index - 1], status: 'completed' };
                    }

                    return { ...prev, [fileId]: currentSteps };
                });
            }, delay);
        });
    }, [initializeProgress]);

    const handleAnalyze = async (fileId: string) => {
        setAnalyzing(fileId);
        setErrors((prev) => ({ ...prev, [fileId]: '' }));
        setElapsedTime(prev => ({ ...prev, [fileId]: 0 }));

        // Initialize and simulate progress
        simulateProgress(fileId);

        try {
            const result = await analyzeFile(fileId);
            setResults((prev) => ({ ...prev, [fileId]: result }));

            // Mark all steps as completed on success
            setProgress(prev => ({
                ...prev,
                [fileId]: (prev[fileId] || []).map(step => ({ ...step, status: 'completed' as const }))
            }));
        } catch (error: any) {
            setErrors((prev) => ({
                ...prev,
                [fileId]: error.response?.data?.detail || 'Analysis failed',
            }));

            // Mark current step as error
            setProgress(prev => {
                const currentSteps = prev[fileId] || [];
                const runningIndex = currentSteps.findIndex(s => s.status === 'running');
                if (runningIndex >= 0) {
                    currentSteps[runningIndex] = { ...currentSteps[runningIndex], status: 'error' };
                }
                return { ...prev, [fileId]: currentSteps };
            });
        } finally {
            setAnalyzing(null);
        }
    };

    const formatDate = (dateStr: string) => {
        return new Date(dateStr).toLocaleString();
    };

    const formatTime = (seconds: number) => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
    };

    const getStepIcon = (step: PipelineStep) => {
        const Icon = step.icon;

        switch (step.status) {
            case 'completed':
                return <CheckCircle className="w-5 h-5 text-green-400" />;
            case 'running':
                return <Loader2 className="w-5 h-5 text-primary-400 animate-spin" />;
            case 'error':
                return <AlertCircle className="w-5 h-5 text-red-400" />;
            default:
                return <Icon className="w-5 h-5 text-gray-500" />;
        }
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div>
                <h1 className="text-3xl font-bold">Analysis Pipeline</h1>
                <p className="text-gray-400 mt-1">
                    Run AI-powered threat analysis on uploaded files with real-time progress tracking
                </p>
            </div>

            {/* Pipeline Overview Card */}
            <div className="card bg-gradient-to-r from-primary-500/10 to-purple-500/10 border-primary-500/30">
                <div className="card-body">
                    <div className="flex items-center justify-between flex-wrap gap-4">
                        {[
                            { step: 1, label: 'Parse CSV', icon: FileText, color: 'bg-blue-500/20 text-blue-400' },
                            { step: 2, label: 'Normalize', icon: Database, color: 'bg-purple-500/20 text-purple-400' },
                            { step: 3, label: 'Chunk', icon: Split, color: 'bg-yellow-500/20 text-yellow-400' },
                            { step: 4, label: 'AI Analysis', icon: Brain, color: 'bg-pink-500/20 text-pink-400' },
                            { step: 5, label: 'Incidents', icon: AlertTriangle, color: 'bg-red-500/20 text-red-400' },
                        ].map((item, index) => (
                            <div key={item.step} className="flex items-center gap-3">
                                <div className="flex flex-col items-center">
                                    <div className={`w-14 h-14 rounded-xl flex items-center justify-center ${item.color}`}>
                                        <item.icon className="w-6 h-6" />
                                    </div>
                                    <span className="text-xs mt-2 text-gray-400 text-center">{item.label}</span>
                                </div>
                                {index < 4 && (
                                    <ArrowRight className="w-5 h-5 text-white/20 hidden md:block" />
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Files List */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">Available Files</h3>
                </div>

                {loading ? (
                    <div className="p-12 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary-400" />
                        <p className="text-gray-400 mt-4">Loading files...</p>
                    </div>
                ) : files.length === 0 ? (
                    <div className="p-12 text-center">
                        <FileText className="w-12 h-12 text-gray-500 mx-auto mb-4" />
                        <p className="text-gray-400">No files uploaded yet</p>
                        <p className="text-sm text-gray-500 mt-1">
                            Upload CSV files to begin analysis
                        </p>
                    </div>
                ) : (
                    <div className="divide-y divide-white/10">
                        {files.map((file) => (
                            <div key={file.file_id} className="p-6">
                                {/* File Header */}
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center gap-4">
                                        <div className="w-14 h-14 bg-blue-500/20 rounded-xl flex items-center justify-center">
                                            <FileText className="w-7 h-7 text-blue-400" />
                                        </div>
                                        <div>
                                            <p className="font-medium text-lg">{file.filename || file.original_filename}</p>
                                            <div className="flex items-center gap-4 text-sm text-gray-400 mt-1">
                                                <span>{file.row_count?.toLocaleString() || 'Unknown'} rows</span>
                                                <span>•</span>
                                                <span>{formatDate(file.uploaded_at)}</span>
                                                <span>•</span>
                                                <span className={`px-2 py-0.5 rounded text-xs ${file.status === 'processed'
                                                    ? 'bg-green-500/20 text-green-400'
                                                    : 'bg-yellow-500/20 text-yellow-400'
                                                    }`}>
                                                    {file.status}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    <button
                                        onClick={() => handleAnalyze(file.file_id)}
                                        disabled={analyzing === file.file_id}
                                        className="btn btn-primary flex items-center gap-2 px-6 py-3"
                                    >
                                        {analyzing === file.file_id ? (
                                            <>
                                                <Loader2 className="w-5 h-5 animate-spin" />
                                                Analyzing...
                                            </>
                                        ) : (
                                            <>
                                                <Play className="w-5 h-5" />
                                                Run Analysis
                                            </>
                                        )}
                                    </button>
                                </div>

                                {/* Live Progress */}
                                {analyzing === file.file_id && progress[file.file_id] && (
                                    <div className="mt-6 p-4 bg-surface-dark rounded-lg border border-primary-500/30">
                                        <div className="flex items-center justify-between mb-4">
                                            <div className="flex items-center gap-2 text-primary-400">
                                                <Loader2 className="w-5 h-5 animate-spin" />
                                                <span className="font-medium">Analysis in Progress</span>
                                            </div>
                                            <div className="flex items-center gap-2 text-gray-400 text-sm">
                                                <Clock className="w-4 h-4" />
                                                <span>{formatTime(elapsedTime[file.file_id] || 0)}</span>
                                            </div>
                                        </div>

                                        {/* Progress Steps */}
                                        <div className="flex items-center justify-between gap-2">
                                            {progress[file.file_id].map((step, index) => (
                                                <div key={step.id} className="flex items-center flex-1">
                                                    <div className={`flex items-center gap-2 p-2 rounded-lg flex-1 ${step.status === 'running'
                                                        ? 'bg-primary-500/10 border border-primary-500/30'
                                                        : step.status === 'completed'
                                                            ? 'bg-green-500/10'
                                                            : step.status === 'error'
                                                                ? 'bg-red-500/10'
                                                                : 'bg-white/5'
                                                        }`}>
                                                        {getStepIcon(step)}
                                                        <span className={`text-xs ${step.status === 'running' ? 'text-primary-400' :
                                                            step.status === 'completed' ? 'text-green-400' :
                                                                step.status === 'error' ? 'text-red-400' :
                                                                    'text-gray-500'
                                                            }`}>
                                                            {step.name}
                                                        </span>
                                                    </div>
                                                    {index < progress[file.file_id].length - 1 && (
                                                        <div className={`w-4 h-0.5 mx-1 ${step.status === 'completed' ? 'bg-green-500' : 'bg-white/10'
                                                            }`} />
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {/* Results */}
                                {results[file.file_id] && (
                                    <div className="mt-6 p-4 bg-green-500/10 rounded-lg border border-green-500/30">
                                        <div className="flex items-center gap-2 text-green-400 mb-4">
                                            <CheckCircle className="w-6 h-6" />
                                            <span className="font-medium text-lg">Analysis Complete</span>
                                            {elapsedTime[file.file_id] && (
                                                <span className="text-sm text-gray-400 ml-2">
                                                    ({formatTime(elapsedTime[file.file_id])})
                                                </span>
                                            )}
                                        </div>
                                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                                            <div className="bg-surface-dark rounded-lg p-3">
                                                <p className="text-xs text-gray-400 uppercase">Events Parsed</p>
                                                <p className="text-2xl font-bold mt-1">
                                                    {results[file.file_id].events_parsed}
                                                </p>
                                            </div>
                                            <div className="bg-surface-dark rounded-lg p-3">
                                                <p className="text-xs text-gray-400 uppercase">Normalized</p>
                                                <p className="text-2xl font-bold mt-1">
                                                    {results[file.file_id].events_normalized}
                                                </p>
                                            </div>
                                            <div className="bg-surface-dark rounded-lg p-3">
                                                <p className="text-xs text-gray-400 uppercase">Chunks</p>
                                                <p className="text-2xl font-bold mt-1">
                                                    {results[file.file_id].chunks_created}
                                                </p>
                                            </div>
                                            <div className="bg-surface-dark rounded-lg p-3">
                                                <p className="text-xs text-gray-400 uppercase">Suspicious</p>
                                                <p className="text-2xl font-bold mt-1 text-yellow-400">
                                                    {results[file.file_id].suspicious_chunks}
                                                </p>
                                            </div>
                                            <div className="bg-surface-dark rounded-lg p-3">
                                                <p className="text-xs text-gray-400 uppercase">Incidents</p>
                                                <p className="text-2xl font-bold mt-1 text-red-400">
                                                    {results[file.file_id].incidents_created}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Errors */}
                                {errors[file.file_id] && (
                                    <div className="mt-6 p-4 bg-red-500/10 rounded-lg border border-red-500/30">
                                        <div className="flex items-center gap-2 text-red-400">
                                            <AlertCircle className="w-5 h-5" />
                                            <span className="font-medium">Analysis Failed</span>
                                        </div>
                                        <p className="mt-2 text-gray-300">{errors[file.file_id]}</p>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
