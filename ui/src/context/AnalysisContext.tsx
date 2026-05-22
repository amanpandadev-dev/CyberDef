import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';

export interface AnalysisProgress {
    step: string;
    percent: number;
    detail?: string;
}

export interface AnalysisState {
    activeFileId: string | null;
    fileName: string | null;
    status: 'idle' | 'uploading' | 'analyzing' | 'complete' | 'error';
    progress: AnalysisProgress;
    startedAt: number | null;
    result: {
        events_parsed?: number;
        events_normalized?: number;
        chunks_created?: number;
        suspicious_chunks?: number;
        ai_analyses?: number;
        incidents_created?: number;
        incident_ids?: string[];
    } | null;
    error: string | null;
}

interface AnalysisContextType {
    state: AnalysisState;
    startAnalysis: (fileId: string, fileName: string) => void;
    updateProgress: (progress: AnalysisProgress) => void;
    completeAnalysis: (result: AnalysisState['result']) => void;
    failAnalysis: (error: string) => void;
    resetAnalysis: () => void;
    isAnalyzing: boolean;
}

const defaultState: AnalysisState = {
    activeFileId: null,
    fileName: null,
    status: 'idle',
    progress: { step: '', percent: 0 },
    startedAt: null,
    result: null,
    error: null,
};

const AnalysisContext = createContext<AnalysisContextType | null>(null);

const STORAGE_KEY = 'cyberdef_analysis_state';

export function AnalysisProvider({ children }: { children: ReactNode }) {
    const [state, setState] = useState<AnalysisState>(() => {
        // Restore from localStorage on init
        try {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) {
                const parsed = JSON.parse(stored);
                // Only restore if analysis was in progress
                if (parsed.status === 'analyzing') {
                    return parsed;
                }
            }
        } catch {
            // Ignore parse errors
        }
        return defaultState;
    });

    // Persist to localStorage on state change
    useEffect(() => {
        if (state.status === 'analyzing') {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
        } else if (state.status === 'idle') {
            localStorage.removeItem(STORAGE_KEY);
        }
    }, [state]);

    const startAnalysis = (fileId: string, fileName: string) => {
        setState({
            activeFileId: fileId,
            fileName: fileName,
            status: 'analyzing',
            progress: { step: 'Starting analysis...', percent: 0 },
            startedAt: Date.now(),
            result: null,
            error: null,
        });
    };

    const updateProgress = (progress: AnalysisProgress) => {
        setState(prev => ({
            ...prev,
            progress,
        }));
    };

    const completeAnalysis = (result: AnalysisState['result']) => {
        setState(prev => ({
            ...prev,
            status: 'complete',
            progress: { step: 'Complete', percent: 100 },
            result,
        }));
        // Clear from localStorage after completion
        localStorage.removeItem(STORAGE_KEY);
    };

    const failAnalysis = (error: string) => {
        setState(prev => ({
            ...prev,
            status: 'error',
            error,
        }));
        localStorage.removeItem(STORAGE_KEY);
    };

    const resetAnalysis = () => {
        setState(defaultState);
        localStorage.removeItem(STORAGE_KEY);
    };

    const isAnalyzing = state.status === 'analyzing';

    return (
        <AnalysisContext.Provider value={{
            state,
            startAnalysis,
            updateProgress,
            completeAnalysis,
            failAnalysis,
            resetAnalysis,
            isAnalyzing,
        }}>
            {children}
        </AnalysisContext.Provider>
    );
}

export function useAnalysis() {
    const context = useContext(AnalysisContext);
    if (!context) {
        throw new Error('useAnalysis must be used within AnalysisProvider');
    }
    return context;
}
