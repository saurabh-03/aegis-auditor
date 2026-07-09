'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { AuditReport } from '@/lib/types';
import { ReportView } from '@/components/ReportView';

export default function ReportPage({ params }: { params: { id: string } }) {
  const [report, setReport] = useState<AuditReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .report(params.id)
      .then(setReport)
      .catch((e) => setError(String(e.message ?? e)));
  }, [params.id]);

  if (error) return <div className="card p-8 text-center text-mute">Report not found.</div>;
  if (!report) return <div className="card p-8 text-center text-mute">Loading report…</div>;
  return <ReportView report={report} reportId={params.id} />;
}
