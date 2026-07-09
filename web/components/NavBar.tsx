'use client';

import Link from 'next/link';
import { useAuth } from '@/lib/auth';

export function NavBar() {
  const { user, logout, loading } = useAuth();
  return (
    <header className="border-b border-[var(--border)]">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-3">
        <Link href="/" className="flex items-center gap-3">
          <span className="grid h-9 w-9 place-items-center rounded-[10px] bg-gradient-to-br from-[var(--accent)] to-[var(--accent-2)] font-extrabold text-white">
            Æ
          </span>
          <div className="leading-tight">
            <div className="font-bold">Aegis Auditor</div>
            <div className="text-[11px] text-mute">Defensive security · performance · scalability</div>
          </div>
        </Link>
        <nav className="flex items-center gap-3 text-sm">
          {!loading && user ? (
            <>
              <Link href="/dashboard" className="text-dim hover:text-ink">
                Dashboard
              </Link>
              <span className="text-mute">·</span>
              <span className="text-dim">{user.name ?? user.email}</span>
              <button onClick={logout} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-dim hover:text-ink">
                Log out
              </button>
            </>
          ) : (
            <>
              <Link href="/login" className="text-dim hover:text-ink">
                Log in
              </Link>
              <Link href="/register" className="btn-primary rounded-lg px-4 py-1.5 font-semibold">
                Sign up
              </Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}
