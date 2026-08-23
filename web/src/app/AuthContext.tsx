import { createContext, useContext, useEffect, useMemo, useState, type PropsWithChildren } from 'react';
import { authApi } from '../api/resources';
import { ApiError } from '../api/client';
import type { User } from '../api/types';

interface AuthState {
  user?: User;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  updateUser: (user: User) => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: PropsWithChildren) {
  const [user, setUser] = useState<User>();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    authApi.me().then(setUser).catch((error) => {
      if (!(error instanceof ApiError) || error.status !== 401) console.error(error);
    }).finally(() => setLoading(false));
  }, []);

  const value = useMemo<AuthState>(() => ({
    user,
    loading,
    login: async (username, password) => setUser(await authApi.login(username, password)),
    logout: async () => {
      try { await authApi.logout(); } catch (error) {
        // A password change revokes the current session before the UI logs out.
        if (!(error instanceof ApiError) || error.status !== 401) throw error;
      } finally { setUser(undefined); }
    },
    updateUser: (updated) => setUser(updated),
  }), [user, loading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used in AuthProvider');
  return value;
}
