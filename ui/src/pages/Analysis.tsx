import { useEffect, useState } from 'react';
import { Download, Eye, FileJson, FileText, Loader2 } from 'lucide-react';
import { getFileIncidentsJsonUrl, getFileReportContent, getFileReportUrl, getFiles } from '../api';
import { formatISTDateTime } from '../utils/datetime';

interface FileData {
    file_id: string;
    original_filename: string;
    filename?: string;
    status?: string;
    row_count?: number | null;
    uploaded_at: string;
}

interface ReportContent {
    content: string;
}

export default function Analysis() {
    const [files, setFiles] = useState<FileData[]>([]);
    const [loading, setLoading] = useState(true);
    const [reportContent, setReportContent] = useState<Record<string, string>>({});
    const [reportLoading, setReportLoading] = useState<Record<string, boolean>>({});

    useEffect(() => {
        const fetchFiles = async () => {
            try {
                const data = await getFiles();
                setFiles(data || []);
            } catch (error) {
                console.error('Failed to fetch files:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchFiles();
    }, []);

    const loadReportContent = async (fileId: string) => {
        setReportLoading((prev) => ({ ...prev, [fileId]: true }));
        try {
            const report = (await getFileReportContent(fileId)) as ReportContent;
            setReportContent((prev) => ({ ...prev, [fileId]: report.content || '' }));
        } catch {
            setReportContent((prev) => ({ ...prev, [fileId]: '' }));
        } finally {
            setReportLoading((prev) => ({ ...prev, [fileId]: false }));
        }
    };

    const sortedFiles = [...files].sort(
        (a, b) => new Date(b.uploaded_at).getTime() - new Date(a.uploaded_at).getTime(),
    );

    return (
        <div className="space-y-8">
            <div>
                <h1 className="text-3xl font-bold">Analysis</h1>
                <p className="mt-1 text-slate-600">
                    Review processed files and access Markdown/JSON reports. The Run Analysis button has been removed as requested.
                </p>
            </div>

            <div className="card">
                <div className="card-header">Processed Log Files</div>
                {loading ? (
                    <div className="p-10 text-center">
                        <Loader2 className="h-8 w-8 animate-spin mx-auto text-primary-500" />
                        <p className="mt-3 text-slate-500">Loading files...</p>
                    </div>
                ) : sortedFiles.length === 0 ? (
                    <div className="p-10 text-center">
                        <FileText className="h-10 w-10 mx-auto text-slate-500 mb-3" />
                        <p className="text-slate-500">No files uploaded yet.</p>
                    </div>
                ) : (
                    <div className="divide-y divide-slate-200">
                        {sortedFiles.map((file) => (
                            <div key={file.file_id} className="p-5 space-y-4">
                                <div className="flex flex-wrap items-center justify-between gap-3">
                                    <div>
                                        <p className="text-base font-semibold text-slate-900">
                                            {file.filename || file.original_filename}
                                        </p>
                                        <p className="text-xs text-slate-500 mt-1">
                                            {formatISTDateTime(file.uploaded_at)} | Rows: {file.row_count || 0}
                                        </p>
                                    </div>
                                    <span
                                        className={`rounded-full px-3 py-1 text-xs font-semibold ${
                                            file.status === 'processed'
                                                ? 'bg-emerald-100 text-emerald-700'
                                                : 'bg-amber-100 text-amber-700'
                                        }`}
                                    >
                                        {(file.status || 'pending').toUpperCase()}
                                    </span>
                                </div>

                                <div className="flex flex-wrap gap-2">
                                    <button
                                        onClick={() => loadReportContent(file.file_id)}
                                        className="btn btn-secondary text-xs px-3 py-2"
                                    >
                                        <Eye className="w-4 h-4" />
                                        {reportLoading[file.file_id] ? 'Loading...' : 'View MD'}
                                    </button>
                                    <a
                                        href={getFileReportUrl(file.file_id, false)}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="btn btn-secondary text-xs px-3 py-2"
                                    >
                                        <Eye className="w-4 h-4" />
                                        Open MD
                                    </a>
                                    <a href={getFileReportUrl(file.file_id, true)} className="btn btn-primary text-xs px-3 py-2">
                                        <Download className="w-4 h-4" />
                                        Download MD
                                    </a>
                                    <a
                                        href={getFileIncidentsJsonUrl(file.file_id, false)}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="btn btn-secondary text-xs px-3 py-2"
                                    >
                                        <FileJson className="w-4 h-4" />
                                        Open JSON
                                    </a>
                                    <a href={getFileIncidentsJsonUrl(file.file_id, true)} className="btn btn-secondary text-xs px-3 py-2">
                                        <Download className="w-4 h-4" />
                                        Download JSON
                                    </a>
                                </div>

                                {reportContent[file.file_id] && (
                                    <pre className="report-markdown">{reportContent[file.file_id]}</pre>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
