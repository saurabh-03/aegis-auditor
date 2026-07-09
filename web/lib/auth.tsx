'use client';

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, setToken } from './api';
import type { Organization, User } from './types';

interface AuthState {
  user: User | null;
  orgs: Organization[];
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);

  async function refresh() {
    try {
      const me = await api.me();
      setUser(me.user);
      setOrgs(me.organizations);
    } catch {
      setUser(null);
      setOrgs([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function login(email: string, password: string) {
    const res = await api.login(email, password);
    setToken(res.accessToken);
    await refresh();
  }
  async function register(email: string, password: string, name: string) {
    const res = await api.register(email, password, name);
    setToken(res.accessToken);
    await refresh();
  }
  function logout() {
    setToken(null);
    setUser(null);
    setOrgs([]);
  }

  return (
    <AuthContext.Provider value={{ user, orgs, loading, login, register, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
