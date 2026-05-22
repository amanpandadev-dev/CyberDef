import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type ThemePreference = 'dark' | 'light' | 'system';
export type ResolvedTheme = 'dark' | 'light';

interface ThemeContextValue {
    preference: ThemePreference;
    resolvedTheme: ResolvedTheme;
    setPreference: (theme: ThemePreference) => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);
const STORAGE_KEY = 'cyberdef-theme-preference';

function resolveSystemTheme(): ResolvedTheme {
    if (typeof window === 'undefined') return 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyThemeClass(theme: ResolvedTheme) {
    const root = document.documentElement;
    root.classList.remove('theme-dark', 'theme-light');
    root.classList.add(theme === 'dark' ? 'theme-dark' : 'theme-light');
}

export function ThemeProvider({ children }: { children: ReactNode }) {
    const [preference, setPreferenceState] = useState<ThemePreference>(() => {
        if (typeof window === 'undefined') return 'dark';
        const saved = window.localStorage.getItem(STORAGE_KEY) as ThemePreference | null;
        return saved || 'dark';
    });
    const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(() => resolveSystemTheme());

    useEffect(() => {
        const media = window.matchMedia('(prefers-color-scheme: dark)');
        const update = () => setSystemTheme(media.matches ? 'dark' : 'light');
        media.addEventListener('change', update);
        return () => media.removeEventListener('change', update);
    }, []);

    const resolvedTheme: ResolvedTheme = preference === 'system' ? systemTheme : preference;

    useEffect(() => {
        window.localStorage.setItem(STORAGE_KEY, preference);
    }, [preference]);

    useEffect(() => {
        applyThemeClass(resolvedTheme);
    }, [resolvedTheme]);

    const value = useMemo(
        () => ({
            preference,
            resolvedTheme,
            setPreference: setPreferenceState,
        }),
        [preference, resolvedTheme],
    );

    return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
    const ctx = useContext(ThemeContext);
    if (!ctx) {
        throw new Error('useTheme must be used within ThemeProvider');
    }
    return ctx;
}
