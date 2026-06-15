import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { AuthUser, AuthTeam } from '@/types';
import * as api from '@/lib/api';

interface AuthState {
  user: AuthUser | null;
  teams: AuthTeam[];
  activeTeamId: string | null;
  loading: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  switchTeam: (teamId: string) => void;
  refreshUser: () => Promise<void>;
  isAdmin: boolean;
  isAnalystOrAbove: boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    teams: [],
    activeTeamId: localStorage.getItem('snr_active_team'),
    loading: true,
    error: null,
  });

  // Try to restore session from stored token on mount
  const refreshUser = useCallback(async () => {
    const token = localStorage.getItem('snr_token');
    if (!token) {
      setState((s) => ({ ...s, loading: false }));
      return;
    }
    try {
      const data = await api.fetchMe();
      const teams = data.teams as AuthTeam[];
      const storedTeam = localStorage.getItem('snr_active_team');
      let activeTeamId = storedTeam;
      // Validate stored team is in user's teams
      if (!activeTeamId || !teams.some((t) => t.id === activeTeamId)) {
        activeTeamId = teams[0]?.id ?? null;
        if (activeTeamId) localStorage.setItem('snr_active_team', activeTeamId);
        else localStorage.removeItem('snr_active_team');
      }
      setState({
        user: data.user as AuthUser,
        teams,
        activeTeamId,
        loading: false,
        error: null,
      });
    } catch {
      // Token invalid or expired
      localStorage.removeItem('snr_token');
      localStorage.removeItem('snr_refresh_token');
      localStorage.removeItem('snr_active_team');
      setState({ user: null, teams: [], activeTeamId: null, loading: false, error: null });
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = useCallback(async (email: string, password: string) => {
    setState((s) => ({ ...s, error: null, loading: true }));
    try {
      const data = await api.login(email, password);
      localStorage.setItem('snr_token', data.token);
      localStorage.setItem('snr_refresh_token', data.refreshToken);
      const teams = data.teams as AuthTeam[];
      const activeTeamId = teams[0]?.id ?? null;
      if (activeTeamId) localStorage.setItem('snr_active_team', activeTeamId);
      setState({
        user: data.user as AuthUser,
        teams,
        activeTeamId,
        loading: false,
        error: null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Login failed';
      setState((s) => ({ ...s, loading: false, error: message }));
      throw err;
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('snr_token');
    localStorage.removeItem('snr_refresh_token');
    localStorage.removeItem('snr_active_team');
    setState({ user: null, teams: [], activeTeamId: null, loading: false, error: null });
  }, []);

  const switchTeam = useCallback((teamId: string) => {
    localStorage.setItem('snr_active_team', teamId);
    setState((s) => ({ ...s, activeTeamId: teamId }));
  }, []);

  const isAdmin = state.user?.role === 'admin';
  const isAnalystOrAbove = state.user?.role === 'admin' || state.user?.role === 'analyst';

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
        logout,
        switchTeam,
        refreshUser,
        isAdmin,
        isAnalystOrAbove,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
