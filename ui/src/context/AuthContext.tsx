import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
    getCurrentUser,
    getStoredAuthToken,
    loginRequest,
    logoutRequest,
    setAuthToken,
} from '../api';

interface AuthUser {
    username: string;
    emp_id?: string | null;
    name: string;
}

interface AuthContextValue {
    isAuthenticated: boolean;
    isInitializing: boolean;
    username: string | null;
    empId: string | null;
    displayName: string | null;
    login: (username: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
    const [user, setUser] = useState<AuthUser | null>(null);
    const [isInitializing, setIsInitializing] = useState(true);

    useEffect(() => {
        const initializeAuth = async () => {
            const token = getStoredAuthToken();
            if (!token) {
                setIsInitializing(false);
                return;
            }

            setAuthToken(token);
            try {
                const currentUser = await getCurrentUser();
                setUser({
                    username: currentUser.username,
                    emp_id: currentUser.emp_id ?? null,
                    name: currentUser.name,
                });
            } catch {
                setAuthToken(null);
                setUser(null);
            } finally {
                setIsInitializing(false);
            }
        };

        void initializeAuth();
    }, []);

    const login = async (submittedUsername: string, password: string) => {
        const data = await loginRequest(submittedUsername, password);
        setAuthToken(data.access_token);
        setUser({
            username: data.username,
            emp_id: data.emp_id ?? null,
            name: data.name,
        });
    };

    const logout = async () => {
        try {
            await logoutRequest();
        } catch {
            // Best effort logout with local token cleanup.
        } finally {
            setAuthToken(null);
            setUser(null);
        }
    };

    const value = useMemo(
        () => ({
            isAuthenticated: Boolean(user?.username),
            isInitializing,
            username: user?.username ?? null,
            empId: user?.emp_id ?? null,
            displayName: user?.name ?? null,
            login,
            logout,
        }),
        [isInitializing, user],
    );

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within AuthProvider');
    }
    return context;
}
