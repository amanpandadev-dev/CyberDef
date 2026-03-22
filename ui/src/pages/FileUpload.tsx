import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileText, CheckCircle, XCircle, Loader2, ArrowRight } from 'lucide-react';
import { uploadFile, analyzeFile } from '../api';

interface UploadedFile {
    file_id: string;
    filename: string;
    status: 'uploading' | 'uploaded' | 'analyzing' | 'success' | 'error';
    message: string;
    analysisResult?: {
        events_parsed: number;
        incidents_created: number;
    };
}

export default function FileUpload() {
    const navigate = useNavigate();
    const [dragActive, setDragActive] = useState(false);
    const [uploading, setUploading] = useState(false);
    const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);

    const handleDrag = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setDragActive(true);
        } else if (e.type === 'dragleave') {
            setDragActive(false);
        }
    }, []);

    const handleDrop = useCallback(async (e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);

        const files = Array.from(e.dataTransfer.files).filter(
            (file) => file.name.endsWith('.csv')
        );

        if (files.length > 0) {
            await handleUpload(files);
        }
    }, []);

    const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const files = Array.from(e.target.files || []);
        if (files.length > 0) {
            await handleUpload(files);
        }
    };

    const handleUpload = async (files: File[]) => {
        setUploading(true);

        for (const file of files) {
            const tempId = `temp-${Date.now()}`;

            // Add file with uploading status
            setUploadedFiles((prev) => [
                {
                    file_id: tempId,
                    filename: file.name,
                    status: 'uploading',
                    message: 'Uploading file...',
                },
                ...prev,
            ]);

            try {
                // Step 1: Upload file
                const result = await uploadFile(file);

                // Update to uploaded status
                setUploadedFiles((prev) =>
                    prev.map((f) =>
                        f.file_id === tempId
                            ? { ...f, file_id: result.file_id, status: 'analyzing', message: 'Running AI analysis...' }
                            : f
                    )
                );

                // Step 2: Auto-run analysis
                try {
                    const analysisResult = await analyzeFile(result.file_id);

                    // Update to success with analysis results
                    setUploadedFiles((prev) =>
                        prev.map((f) =>
                            f.file_id === result.file_id
                                ? {
                                    ...f,
                                    status: 'success',
                                    message: `Analysis complete! ${analysisResult.incidents_created} incidents detected`,
                                    analysisResult: {
                                        events_parsed: analysisResult.events_parsed,
                                        incidents_created: analysisResult.incidents_created,
                                    },
                                }
                                : f
                        )
                    );
                } catch (analysisError: any) {
                    // Analysis failed but upload succeeded
                    setUploadedFiles((prev) =>
                        prev.map((f) =>
                            f.file_id === result.file_id
                                ? {
                                    ...f,
                                    status: 'uploaded',
                                    message: 'Uploaded. Analysis failed: ' + (analysisError.response?.data?.detail || analysisError.message),
                                }
                                : f
                        )
                    );
                }
            } catch (error: any) {
                // Upload failed
                setUploadedFiles((prev) =>
                    prev.map((f) =>
                        f.file_id === tempId
                            ? {
                                ...f,
                                status: 'error',
                                message: error.response?.data?.detail || 'Upload failed',
                            }
                            : f
                    )
                );
            }
        }

        setUploading(false);
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'uploading':
            case 'analyzing':
                return <Loader2 className="w-5 h-5 text-primary-400 animate-spin" />;
            case 'success':
                return <CheckCircle className="w-5 h-5 text-green-400" />;
            case 'uploaded':
                return <CheckCircle className="w-5 h-5 text-yellow-400" />;
            case 'error':
                return <XCircle className="w-5 h-5 text-red-400" />;
            default:
                return null;
        }
    };

    const getStatusBg = (status: string) => {
        switch (status) {
            case 'uploading':
            case 'analyzing':
                return 'bg-primary-500/20';
            case 'success':
                return 'bg-green-500/20';
            case 'uploaded':
                return 'bg-yellow-500/20';
            case 'error':
                return 'bg-red-500/20';
            default:
                return 'bg-surface-dark';
        }
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div>
                <h1 className="text-3xl font-bold">File Upload</h1>
                <p className="text-gray-400 mt-1">
                    Upload CSV log files for AI-powered threat analysis (auto-starts on upload)
                </p>
            </div>

            {/* Upload Area */}
            <div
                className={`card p-12 transition-all duration-300 ${dragActive
                    ? 'border-primary-500 bg-primary-500/10'
                    : 'border-dashed border-2 border-white/20 hover:border-white/40'
                    }`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
            >
                <div className="flex flex-col items-center text-center">
                    <div className={`w-20 h-20 rounded-2xl flex items-center justify-center mb-6 transition-colors ${dragActive ? 'bg-primary-500/20' : 'bg-surface-light'
                        }`}>
                        {uploading ? (
                            <Loader2 className="w-10 h-10 text-primary-400 animate-spin" />
                        ) : (
                            <Upload className={`w-10 h-10 ${dragActive ? 'text-primary-400' : 'text-gray-400'}`} />
                        )}
                    </div>

                    <h3 className="text-xl font-semibold mb-2">
                        {uploading ? 'Processing...' : 'Drop your CSV files here'}
                    </h3>
                    <p className="text-gray-400 mb-6">
                        Files are automatically analyzed after upload
                    </p>

                    <label className="btn btn-primary cursor-pointer">
                        <input
                            type="file"
                            className="hidden"
                            accept=".csv"
                            multiple
                            onChange={handleFileSelect}
                            disabled={uploading}
                        />
                        Select Files
                    </label>

                    <p className="text-sm text-gray-500 mt-4">
                        Supported format: CSV (max 500MB per file)
                    </p>
                </div>
            </div>

            {/* Uploaded Files */}
            {uploadedFiles.length > 0 && (
                <div className="card">
                    <div className="card-header flex justify-between items-center">
                        <h3 className="font-semibold">Upload & Analysis Results</h3>
                        {uploadedFiles.some(f => f.status === 'success' && f.analysisResult?.incidents_created) && (
                            <button
                                onClick={() => navigate('/incidents')}
                                className="btn btn-primary btn-sm flex items-center gap-2"
                            >
                                View Incidents
                                <ArrowRight className="w-4 h-4" />
                            </button>
                        )}
                    </div>
                    <div className="divide-y divide-white/10">
                        {uploadedFiles.map((file, index) => (
                            <div
                                key={`${file.filename}-${index}`}
                                className="p-4"
                            >
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${getStatusBg(file.status)}`}>
                                            {getStatusIcon(file.status)}
                                        </div>
                                        <div>
                                            <p className="font-medium">{file.filename}</p>
                                            <p className={`text-sm ${file.status === 'success' ? 'text-green-400' :
                                                file.status === 'error' ? 'text-red-400' :
                                                    file.status === 'analyzing' || file.status === 'uploading' ? 'text-primary-400' :
                                                        'text-yellow-400'
                                                }`}>
                                                {file.message}
                                            </p>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4">
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
                                        {file.file_id && !file.file_id.startsWith('temp-') && (
                                            <code className="text-xs text-gray-500 bg-surface-dark px-2 py-1 rounded">
                                                {file.file_id.slice(0, 8)}...
                                            </code>
                                        )}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Instructions */}
            <div className="card">
                <div className="card-header">
                    <h3 className="font-semibold">Supported Log Formats</h3>
                </div>
                <div className="card-body">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="flex items-start gap-4">
                            <div className="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                                <FileText className="w-5 h-5 text-blue-400" />
                            </div>
                            <div>
                                <p className="font-medium">Firewall Logs</p>
                                <p className="text-sm text-gray-400 mt-1">
                                    Palo Alto, Fortinet, Cisco ASA exports
                                </p>
                            </div>
                        </div>

                        <div className="flex items-start gap-4">
                            <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                                <FileText className="w-5 h-5 text-purple-400" />
                            </div>
                            <div>
                                <p className="font-medium">Network Flow</p>
                                <p className="text-sm text-gray-400 mt-1">
                                    NetFlow, IPFIX, connection logs
                                </p>
                            </div>
                        </div>

                        <div className="flex items-start gap-4">
                            <div className="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                                <FileText className="w-5 h-5 text-green-400" />
                            </div>
                            <div>
                                <p className="font-medium">Generic CSV</p>
                                <p className="text-sm text-gray-400 mt-1">
                                    Any CSV with standard network fields
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
