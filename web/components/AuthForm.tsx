'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/lib/auth';
import { ApiError } from '@/lib/api';

export function AuthForm({ mode }: { mode: 'login' | 'register' }) {
  const { login, register } = useAuth();
  const router = useRouter();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'register') await register(email, password, name);
      else await login(email, password);
      router.push('/dashboard');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md">
      <div className="card p-7">
        <h1 className="mb-1 text-xl font-bold">{mode === 'register' ? 'Create your account' : 'Welcome back'}</h1>
        <p className="mb-5 text-sm text-mute">{mode === 'register' ? 'Start auditing your sites in minutes.' : 'Log in to your dashboard.'}</p>
        <form onSubmit={submit} className="space-y-3">
          {mode === 'register' && (
            <input className="input w-full" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          )}
          <input className="input w-full" type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          <input className="input w-full" type="password" placeholder="Password (min 8 chars)" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
          {error && <p className="text-sm text-[var(--red)]">{error}</p>}
          <button disabled={busy} className="btn-primary w-full rounded-lg py-2.5 font-semibold disabled:opacity-50">
            {busy ? 'Please wait…' : mode === 'register' ? 'Sign up' : 'Log in'}
          </button>
        </form>
        <p className="mt-4 text-center text-sm text-mute">
          {mode === 'register' ? (
            <>Already have an account? <Link href="/login" className="text-accent hover:underline">Log in</Link></>
          ) : (
            <>No account? <Link href="/register" className="text-accent hover:underline">Sign up</Link></>
          )}
        </p>
        <div className="mt-4 border-t border-[var(--border)] pt-4 text-center text-xs text-mute">
          Or continue with{' '}
          <a href="/api/auth/oauth/google" className="text-accent hover:underline">Google</a> ·{' '}
          <a href="/api/auth/oauth/github" className="text-accent hover:underline">GitHub</a>
        </div>
      </div>
    </div>
  );
}
