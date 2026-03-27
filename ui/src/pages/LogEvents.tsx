import { useEffect, useMemo, useState } from 'react';
import { FileText, Eye, Download, Loader2, FileJson } from 'lucide-react';
import {
    getFileIncidentsJsonContent,
    getFileIncidentsJsonUrl,
    getFileReportContent,
    getFileReportUrl,
    getFiles,
    listGeneratedReports,
} from '../api';
import { formatISTDateTime } from '../utils/datetime';

interface FileData {
    file_id: string;
    filename?: string;
    original_filename?: string;
    status?: string;
    uploaded_at: string;
    row_count?: number | null;
}

interface ReportMap {
    [fileId: string]: boolean;
}

const normalizeValue = (value?: string | null) => (value || '').trim().toLowerCase();

const toStem = (name?: string) =>
    normalizeValue(name)
        .replace(/\.[^./\\]+$/, '')
        .replace(/\s+/g, '_');

export default function LogEvents() {
    const [files, setFiles] = useState<FileData[]>([]);
    const [loading, setLoading] = useState(true);
    const [hasReport, setHasReport] = useState<ReportMap>({});
    const [previewTitle, setPreviewTitle] = useState<string>('');
    const [previewMarkdown, setPreviewMarkdown] = useState<string>('');
    const [previewJson, setPreviewJson] = useState<any>(null);
    const [previewLoading, setPreviewLoading] = useState(false);
    const [previewError, setPreviewError] = useState<string>('');
    const [nameFilter, setNameFilter] = useState('');
    const [dateFrom, setDateFrom] = useState('');
    const [dateTo, setDateTo] = useState('');
    const [sortBy, setSortBy] = useState<'recent' | 'oldest' | 'name'>('recent');

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [filesData, reportsData] = await Promise.all([
                    getFiles().catch(() => []),
                    listGeneratedReports().catch(() => []),
                ]);
                const normalizedFiles = filesData || [];
                const normalizedReports = (reportsData || []).map((report: any) => ({
                    fileId: normalizeValue(report.file_id),
                    reportName: normalizeValue(report.report_name),
                    reportPath: normalizeValue(report.report_path),
                }));

                setFiles(normalizedFiles);

                const map: ReportMap = {};
                normalizedFiles.forEach((file: FileData) => {
                    const normalizedFileId = normalizeValue(file.file_id);
                    const fileStem = toStem(file.filename || file.original_filename);
                    const isProcessed = normalizeValue(file.status) === 'processed';

                    map[file.file_id] = isProcessed || normalizedReports.some((report: any) => {
                        if (report.fileId && report.fileId === normalizedFileId) return true;
                        if (normalizedFileId && (report.reportName.includes(normalizedFileId) || report.reportPath.includes(normalizedFileId))) {
                            return true;
                        }
                        if (fileStem && report.reportName.includes(fileStem)) return true;
                        return false;
                    });
                });
                setHasReport(map);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    const handlePreviewMarkdown = async (file: FileData) => {
        setPreviewLoading(true);
        setPreviewError('');
        setPreviewJson(null);
        try {
            const report = await getFileReportContent(file.file_id);
            setPreviewTitle(`Markdown: ${file.filename || file.original_filename || file.file_id}`);
            setPreviewMarkdown(report.content || '');
        } catch (error: any) {
            setPreviewMarkdown('');
            setPreviewError(error?.response?.data?.detail || 'Markdown report is not available.');
        } finally {
            setPreviewLoading(false);
        }
    };

    const handlePreviewJson = async (file: FileData) => {
        setPreviewLoading(true);
        setPreviewError('');
        setPreviewMarkdown('');
        try {
            const payload = await getFileIncidentsJsonContent(file.file_id);
            setPreviewTitle(`Incident JSON: ${file.filename || file.original_filename || file.file_id}`);
            setPreviewJson(payload);
        } catch (error: any) {
            setPreviewJson(null);
            setPreviewError(error?.response?.data?.detail || 'Incident JSON is not available for this file yet.');
        } finally {
            setPreviewLoading(false);
        }
    };

    const visibleFiles = useMemo(() => {
        let next = [...files];

        if (nameFilter.trim()) {
            const term = nameFilter.trim().toLowerCase();
            next = next.filter((file) =>
                (file.filename || file.original_filename || '').toLowerCase().includes(term),
            );
        }

        if (dateFrom) {
            const fromTs = new Date(`${dateFrom}T00:00:00`).getTime();
            next = next.filter((file) => new Date(file.uploaded_at).getTime() >= fromTs);
        }

        if (dateTo) {
            const toTs = new Date(`${dateTo}T23:59:59`).getTime();
            next = next.filter((file) => new Date(file.uploaded_at).getTime() <= toTs);
        }

        if (sortBy === 'name') {
            next.sort((a, b) =>
                (a.filename || a.original_filename || '').localeCompare(b.filename || b.original_filename || ''),
            );
        } else if (sortBy === 'oldest') {
            next.sort((a, b) => new Date(a.uploaded_at).getTime() - new Date(b.uploaded_at).getTime());
        } else {
            next.sort((a, b) => new Date(b.uploaded_at).getTime() - new Date(a.uploaded_at).getTime());
        }

        return next;
    }, [files, nameFilter, dateFrom, dateTo, sortBy]);

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-3xl font-bold">Analysis</h1>
                <p className="mt-1 text-sm text-slate-600">Uploaded files with report actions (View, Open, Download) for Markdown and JSON outputs.</p>
            </div>

            <div className="card">
                <div className="card-body grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
                    <input
                        value={nameFilter}
                        onChange={(event) => setNameFilter(event.target.value)}
                        className="input"
                        placeholder="Filter by file name"
                    />
                    <input
                        type="date"
                        value={dateFrom}
                        onChange={(event) => setDateFrom(event.target.value)}
                        className="input"
                    />
                    <input
                        type="date"
                        value={dateTo}
                        onChange={(event) => setDateTo(event.target.value)}
                        className="input"
                    />
                    <select
                        value={sortBy}
                        onChange={(event) => setSortBy(event.target.value as 'recent' | 'oldest' | 'name')}
                        className="input"
                    >
                        <option value="recent">Most Recent</option>
                        <option value="oldest">Oldest First</option>
                        <option value="name">File Name</option>
                    </select>
                </div>
            </div>

            <div className="card">
                {loading ? (
                    <div className="p-10 text-center">
                        <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary-400" />
                        <p className="mt-3 text-slate-500">Loading analysis data...</p>
                    </div>
                ) : visibleFiles.length === 0 ? (
                    <div className="p-10 text-center">
                        <FileText className="w-10 h-10 mx-auto text-slate-500 mb-3" />
                        <p className="text-slate-500">No files match the selected filters</p>
                    </div>
                ) : (
                    <div className="divide-y divide-slate-200">
                        {visibleFiles.map((file) => (
                            <div key={file.file_id} className="p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                                <div>
                                    <p className="font-semibold text-slate-900">{file.filename || file.original_filename}</p>
                                    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                                        <span>{formatISTDateTime(file.uploaded_at)}</span>
                                        <span>|</span>
                                        <span>{file.row_count || 0} rows</span>
                                        <span>|</span>
                                        <span className="uppercase">{hasReport[file.file_id] ? 'processed' : file.status || 'pending'}</span>
                                    </div>
                                </div>
                                <div className="flex flex-wrap items-center gap-2">
                                    {hasReport[file.file_id] ? (
                                        <>
                                            <button
                                                onClick={() => handlePreviewMarkdown(file)}
                                                className="btn btn-secondary help-hover px-3 py-2 text-xs"
                                                data-help="Preview markdown report inside this page"
                                            >
                                                <Eye className="w-4 h-4" />
                                                View MD
                                            </button>
                                            <a
                                                href={getFileReportUrl(file.file_id, false)}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="btn btn-secondary help-hover px-3 py-2 text-xs"
                                                data-help="Open markdown report in a new tab"
                                            >
                                                <Eye className="w-4 h-4" />
                                                Open MD
                                            </a>
                                            <a
                                                href={getFileReportUrl(file.file_id, true)}
                                                className="btn btn-primary help-hover px-3 py-2 text-xs"
                                                data-help="Download markdown report for this logevent"
                                            >
                                                <Download className="w-4 h-4" />
                                                Download MD
                                            </a>
                                            <button
                                                onClick={() => handlePreviewJson(file)}
                                                className="btn btn-secondary help-hover px-3 py-2 text-xs"
                                                data-help="Preview incident JSON for this logevent"
                                            >
                                                <FileJson className="w-4 h-4" />
                                                View JSON
                                            </button>
                                            <a
                                                href={getFileIncidentsJsonUrl(file.file_id, false)}
                                                target="_blank"
                                                rel="noreferrer"
                                                className="btn btn-secondary help-hover px-3 py-2 text-xs"
                                                data-help="Open incident JSON in a new tab"
                                            >
                                                <Eye className="w-4 h-4" />
                                                Open JSON
                                            </a>
                                            <a
                                                href={getFileIncidentsJsonUrl(file.file_id, true)}
                                                className="btn btn-secondary help-hover px-3 py-2 text-xs"
                                                data-help="Download incident JSON report"
                                            >
                                                <Download className="w-4 h-4" />
                                                Download JSON
                                            </a>
                                        </>
                                    ) : (
                                        <span className="text-xs px-3 py-1 rounded-full bg-amber-500/20 text-amber-300">Report Pending</span>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {(previewLoading || previewMarkdown || previewJson || previewError) && (
                <div className="card">
                    <div className="card-header">{previewTitle || 'Report Preview'}</div>
                    <div className="card-body">
                        {previewLoading && (
                            <div className="flex items-center gap-2 text-sm text-slate-500">
                                <Loader2 className="h-4 w-4 animate-spin" />
                                Loading preview...
                            </div>
                        )}
                        {previewError && !previewLoading && (
                            <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                                {previewError}
                            </div>
                        )}
                        {previewMarkdown && !previewLoading && <pre className="report-markdown">{previewMarkdown}</pre>}
                        {previewJson && !previewLoading && (
                            <pre className="report-markdown">{JSON.stringify(previewJson, null, 2)}</pre>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
