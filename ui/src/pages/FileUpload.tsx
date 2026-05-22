import { useState, useCallback, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Upload,
    FileText,
    CheckCircle,
    XCircle,
    Loader2,
    ArrowRight,
    Eye,
    Download,
    Clock,
} from 'lucide-react';
import { uploadFile, analyzeFile, getFileReportUrl } from '../api';

type QueueStatus = 'queued' | 'uploading' | 'analyzing' | 'success' | 'error' | 'aborted';

interface QueueItem {
    localId: string;
    file: File | null;
    file_id?: string;
    filename: string;
    status: QueueStatus;
    message: string;
    startedAt?: number;
    finishedAt?: number;
    elapsedMs?: number;
    analysisResult?: {
        events_parsed: number;
        incidents_created: number;
    };
}

export default function FileUpload() {
    const navigate = useNavigate();
    const [dragActive, setDragActive] = useState(false);
    const [queue, setQueue] = useState<QueueItem[]>([]);
    const [isProcessing, setIsProcessing] = useState(false);
    const [timerNow, setTimerNow] = useState(Date.now());
    const activeAbortController = useRef<AbortController | null>(null);
    const activeLocalId = useRef<string | null>(null);

    const queuedCount = queue.filter((item) => item.status === 'queued').length;
    const completedCount = queue.filter((item) => item.status === 'success').length;
    const failedCount = queue.filter((item) => item.status === 'error').length;
    const activeItem = queue.find((item) => item.status === 'uploading' || item.status === 'analyzing');
    const hasIncidents = queue.some((item) => (item.analysisResult?.incidents_created || 0) > 0);

    useEffect(() => {
        if (!activeItem) return;
        const timer = window.setInterval(() => setTimerNow(Date.now()), 1000);
        return () => window.clearInterval(timer);
    }, [activeItem?.localId]);

    const formatElapsed = (ms?: number) => {
        if (ms === undefined) return '0s';
        const totalSeconds = Math.max(0, Math.floor(ms / 1000));
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
    };

    const getElapsedMs = (item: QueueItem) => {
        if (item.elapsedMs !== undefined) return item.elapsedMs;
        if (item.startedAt && (item.status === 'uploading' || item.status === 'analyzing')) {
            return timerNow - item.startedAt;
        }
        return undefined;
    };

    const addToQueue = useCallback((files: File[]) => {
        const csvFiles = files.filter((file) => file.name.toLowerCase().endsWith('.csv'));
        if (csvFiles.length === 0) return;

        const newItems: QueueItem[] = csvFiles.map((file, index) => ({
            localId: `${Date.now()}-${index}-${Math.random().toString(36).slice(2, 8)}`,
            file,
            filename: file.name,
            status: 'queued',
            message: 'Waiting in queue',
        }));

        setQueue((prev) => [...prev, ...newItems]);
    }, []);

    const handleDrag = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setDragActive(true);
        } else if (e.type === 'dragleave') {
            setDragActive(false);
        }
    }, []);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);

        const files = Array.from(e.dataTransfer.files || []);
        addToQueue(files);
    }, [addToQueue]);

    const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
        const files = Array.from(e.target.files || []);
        addToQueue(files);
        e.target.value = '';
    };

    const processItem = useCallback(async (item: QueueItem) => {
        if (!item.file) {
            setQueue((prev) =>
                prev.map((f) =>
                    f.localId === item.localId
                        ? { ...f, status: 'error', message: 'Missing file data' }
                        : f
                )
            );
            return;
        }

        setIsProcessing(true);
        setQueue((prev) =>
            prev.map((f) =>
                f.localId === item.localId
                    ? {
                        ...f,
                        status: 'uploading',
                        message: 'Uploading file...',
                        startedAt: Date.now(),
                        finishedAt: undefined,
                        elapsedMs: undefined,
                    }
                    : f
            )
        );

        const controller = new AbortController();
        activeAbortController.current = controller;
        activeLocalId.current = item.localId;

        try {
            const uploadResult = await uploadFile(item.file, controller.signal);
            setQueue((prev) =>
                prev.map((f) =>
                    f.localId === item.localId
                        ? {
                            ...f,
                            file_id: uploadResult.file_id,
                            status: 'analyzing',
                            message: 'Running AI analysis...',
                        }
                        : f
                )
            );

            const analysisResult = await analyzeFile(uploadResult.file_id, controller.signal);
            const incidentsCreated =
                analysisResult.incidents_created ??
                analysisResult.total_incidents ??
                0;
            const finishedAt = Date.now();

            setQueue((prev) =>
                prev.map((f) =>
                    f.localId === item.localId
                        ? {
                            ...f,
                            status: 'success',
                            message: 'Report ready',
                            finishedAt,
                            elapsedMs: f.startedAt ? finishedAt - f.startedAt : undefined,
                            analysisResult: {
                                events_parsed: analysisResult.events_parsed,
                                incidents_created: incidentsCreated,
                            },
                        }
                        : f
                )
            );
        } catch (error: any) {
            const isCanceled =
                controller.signal.aborted ||
                error?.code === 'ERR_CANCELED' ||
                error?.name === 'CanceledError';
            const message = isCanceled
                ? 'Aborted by user'
                : error.response?.data?.detail || error.message || 'Processing failed';
            const finishedAt = Date.now();
            setQueue((prev) =>
                prev.map((f) =>
                    f.localId === item.localId
                        ? {
                            ...f,
                            status: isCanceled ? 'aborted' : 'error',
                            message,
                            finishedAt,
                            elapsedMs: f.startedAt ? finishedAt - f.startedAt : undefined,
                        }
                        : f
                )
            );
        } finally {
            if (activeLocalId.current === item.localId) {
                activeAbortController.current = null;
                activeLocalId.current = null;
            }
            setIsProcessing(false);
        }
    }, []);

    const abortItem = useCallback((item: QueueItem) => {
        if (item.status === 'queued') {
            setQueue((prev) =>
                prev.map((f) =>
                    f.localId === item.localId
                        ? { ...f, status: 'aborted', message: 'Removed before processing', elapsedMs: 0 }
                        : f
                )
            );
            return;
        }

        if (
            (item.status === 'uploading' || item.status === 'analyzing') &&
            activeLocalId.current === item.localId
        ) {
            activeAbortController.current?.abort();
            setQueue((prev) =>
                prev.map((f) =>
                    f.localId === item.localId ? { ...f, message: 'Aborting...' } : f
                )
            );
        }
    }, []);

    useEffect(() => {
        if (isProcessing) return;
        const nextItem = queue.find((item) => item.status === 'queued');
        if (!nextItem) return;
        processItem(nextItem);
    }, [queue, isProcessing, processItem]);

    const getStatusIcon = (status: QueueStatus) => {
        switch (status) {
            case 'uploading':
            case 'analyzing':
                return <Loader2 className="w-5 h-5 text-primary-400 animate-spin" />;
            case 'success':
                return <CheckCircle className="w-5 h-5 text-green-400" />;
            case 'error':
                return <XCircle className="w-5 h-5 text-red-400" />;
            case 'aborted':
                return <XCircle className="w-5 h-5 text-amber-400" />;
            case 'queued':
            default:
                return <Clock className="w-5 h-5 text-gray-400" />;
        }
    };

    const getStatusTone = (status: QueueStatus) => {
        switch (status) {
            case 'uploading':
            case 'analyzing':
                return 'text-primary-400';
            case 'success':
                return 'text-green-400';
            case 'error':
                return 'text-red-400';
            case 'aborted':
                return 'text-amber-400';
            case 'queued':
            default:
                return 'text-gray-400';
        }
    };

    const getStatusBg = (status: QueueStatus) => {
        switch (status) {
            case 'uploading':
            case 'analyzing':
                return 'bg-primary-500/15';
            case 'success':
                return 'bg-green-500/15';
            case 'error':
                return 'bg-red-500/15';
            case 'aborted':
                return 'bg-amber-500/15';
            case 'queued':
            default:
                return 'bg-white/5';
        }
    };

    const queuedItems = queue.filter((item) => item.status === 'queued');

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex items-start justify-between gap-6 flex-wrap">
                <div>
                    <h1 className="text-3xl font-bold">Upload & Analyze</h1>
                    <p className="text-gray-400 mt-1">
                        Drop CSV files. We process them one by one and generate a report you can view or download.
                    </p>
                </div>
                {queue.length > 0 && (
                    <div className="flex items-center gap-3 flex-wrap">
                        <span className="px-3 py-1 rounded-full text-xs bg-white/10 text-gray-300">
                            Queue: {queuedCount}
                        </span>
                        <span className="px-3 py-1 rounded-full text-xs bg-green-500/10 text-green-300">
                            Done: {completedCount}
                        </span>
                        {activeItem && (
                            <span className="px-3 py-1 rounded-full text-xs bg-primary-500/10 text-primary-300">
                                Time: {formatElapsed(getElapsedMs(activeItem))}
                            </span>
                        )}
                        {failedCount > 0 && (
                            <span className="px-3 py-1 rounded-full text-xs bg-red-500/10 text-red-300">
                                Failed: {failedCount}
                            </span>
                        )}
                    </div>
                )}
            </div>

            {/* Upload Area */}
            <div className="card p-6 md:p-8">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                    <div
                        className={`md:col-span-2 rounded-2xl border-2 border-dashed p-8 text-center transition-all ${dragActive
                            ? 'border-primary-500 bg-primary-500/10'
                            : 'border-white/20 hover:border-white/40'
                            }`}
                        onDragEnter={handleDrag}
                        onDragLeave={handleDrag}
                        onDragOver={handleDrag}
                        onDrop={handleDrop}
                    >
                        <div className="flex flex-col items-center gap-3">
                            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${dragActive ? 'bg-primary-500/20' : 'bg-surface-light'
                                }`}>
                                {isProcessing ? (
                                    <Loader2 className="w-8 h-8 text-primary-400 animate-spin" />
                                ) : (
                                    <Upload className={`w-8 h-8 ${dragActive ? 'text-primary-400' : 'text-gray-400'}`} />
                                )}
                            </div>

                            <div>
                                <h3 className="text-lg font-semibold">
                                    {isProcessing ? 'Processing queue...' : 'Drop CSV files here'}
                                </h3>
                                <p className="text-gray-400 text-sm mt-1">
                                    Add more files anytime. The queue keeps moving even if one file fails.
                                </p>
                            </div>

                            <label
                                className="btn btn-primary help-hover cursor-pointer mt-2"
                                data-help="Choose CSV files from your machine and add them to queue"
                            >
                                <input
                                    type="file"
                                    className="hidden"
                                    accept=".csv"
                                    multiple
                                    onChange={handleFileSelect}
                                />
                                Select Files
                            </label>

                            {activeItem && (
                                <div className="mt-2 flex flex-wrap items-center justify-center gap-3 text-xs text-primary-300">
                                    <span>Now processing: {activeItem.filename}</span>
                                    <span>Elapsed: {formatElapsed(getElapsedMs(activeItem))}</span>
                                    <button
                                        type="button"
                                        className="rounded-lg border border-amber-400/40 px-2.5 py-1 font-semibold text-amber-300 transition hover:bg-amber-500/10"
                                        onClick={() => abortItem(activeItem)}
                                    >
                                        Abort
                                    </button>
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="space-y-4 text-sm text-gray-300">
                        <div className="flex items-center gap-3">
                            <span className="w-7 h-7 rounded-full bg-primary-500/20 text-primary-300 flex items-center justify-center text-xs font-bold">1</span>
                            <span>Upload CSV logs</span>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="w-7 h-7 rounded-full bg-primary-500/20 text-primary-300 flex items-center justify-center text-xs font-bold">2</span>
                            <span>AI analysis runs automatically</span>
                        </div>
                        <div className="flex items-center gap-3">
                            <span className="w-7 h-7 rounded-full bg-primary-500/20 text-primary-300 flex items-center justify-center text-xs font-bold">3</span>
                            <span>View or download the report</span>
                        </div>
                        <p className="text-xs text-gray-500">
                            CSV up to 500MB per file.
                        </p>
                    </div>
                </div>
            </div>

            {/* Queue */}
            <div className="card">
                <div className="card-header flex items-center justify-between gap-4 flex-wrap">
                    <h3 className="font-semibold">Processing Queue</h3>
                    {hasIncidents && (
                        <button
                            onClick={() => navigate('/incidents')}
                            className="btn btn-primary help-hover px-3 py-2 text-xs flex items-center gap-2"
                            data-help="Open incidents page to navigate analysis results"
                        >
                            View Incidents
                            <ArrowRight className="w-4 h-4" />
                        </button>
                    )}
                </div>
                {queue.length === 0 ? (
                    <div className="p-10 text-center">
                        <FileText className="w-10 h-10 text-gray-500 mx-auto mb-3" />
                        <p className="text-gray-400">No files in the queue yet</p>
                        <p className="text-xs text-gray-500 mt-1">Drop or select CSV files to begin.</p>
                    </div>
                ) : (
                    <div className="divide-y divide-white/10">
                        {queue.map((file) => {
                            const queuedIndex = queuedItems.findIndex((item) => item.localId === file.localId);

                            return (
                                <div
                                    key={file.localId}
                                    className="p-4 flex flex-col gap-4 md:flex-row md:items-center md:justify-between"
                                >
                                    <div className="flex items-center gap-4">
                                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getStatusBg(file.status)}`}>
                                            {getStatusIcon(file.status)}
                                        </div>
                                        <div>
                                            <p className="font-medium">{file.filename}</p>
                                            <p className={`text-sm ${getStatusTone(file.status)}`}>
                                                {file.message}
                                            </p>
                                            {file.status === 'queued' && queuedIndex >= 0 && (
                                                <p className="text-xs text-gray-500 mt-1">Queue position #{queuedIndex + 1}</p>
                                            )}
                                            {file.startedAt && (
                                                <p className="text-xs text-gray-500 mt-1">
                                                    Time taken: {formatElapsed(getElapsedMs(file))}
                                                </p>
                                            )}
                                        </div>
                                    </div>

                                    <div className="flex flex-wrap items-center gap-4">
                                        {(file.status === 'queued' || file.status === 'uploading' || file.status === 'analyzing') && (
                                            <button
                                                type="button"
                                                onClick={() => abortItem(file)}
                                                className="btn btn-secondary help-hover px-3 py-2 text-xs flex items-center gap-2 text-amber-300"
                                                data-help="Abort this upload or analysis item"
                                            >
                                                <XCircle className="w-4 h-4" />
                                                Abort
                                            </button>
                                        )}

                                        {file.analysisResult && (
                                            <div className="flex gap-4 text-sm">
                                                <div className="text-center">
                                                    <p className="text-gray-400">Events</p>
                                                    <p className="font-bold">{file.analysisResult.events_parsed}</p>
                                                </div>
                                                <div className="text-center">
                                                    <p className="text-gray-400">Incidents</p>
                                                    <p className={`font-bold ${file.analysisResult.incidents_created > 0 ? 'text-red-400' : 'text-green-400'}`}>
                                                        {file.analysisResult.incidents_created}
                                                    </p>
                                                </div>
                                            </div>
                                        )}

                                        {file.file_id && (
                                            <code className="text-xs text-gray-500 bg-surface-dark px-2 py-1 rounded">
                                                {file.file_id.slice(0, 8)}...
                                            </code>
                                        )}

                                        {file.status === 'success' && file.file_id && (
                                            <div className="flex items-center gap-2">
                                                <a
                                                    href={getFileReportUrl(file.file_id, false)}
                                                    target="_blank"
                                                    rel="noreferrer"
                                                    className="btn btn-secondary help-hover px-3 py-2 text-xs flex items-center gap-2"
                                                    data-help="Open markdown report in browser"
                                                >
                                                    <Eye className="w-4 h-4" />
                                                    View
                                                </a>
                                                <a
                                                    href={getFileReportUrl(file.file_id, true)}
                                                    className="btn btn-primary help-hover px-3 py-2 text-xs flex items-center gap-2"
                                                    data-help="Download generated markdown report"
                                                >
                                                    <Download className="w-4 h-4" />
                                                    Download
                                                </a>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* Supported Formats */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">Supported Logs</h3>
                </div>
                <div className="card-body text-sm text-gray-300">
                    Firewall exports, network flow logs, and generic CSV logs with standard network fields.
                </div>
            </div>
        </div>
    );
}
