import type { Metadata } from 'next';
import './globals.css';
import { AuthProvider } from '@/lib/auth';
import { NavBar } from '@/components/NavBar';

export const metadata: Metadata = {
  title: 'Aegis Auditor',
  description: 'Defensive website security, performance, and scalability auditing.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans">
        <AuthProvider>
          <NavBar />
          <main className="mx-auto max-w-6xl px-5 pb-24 pt-6">{children}</main>
        </AuthProvider>
      </body>
    </html>
  );
}
