'use client';

import { useEffect, useRef, useState } from 'react';
import { scanStreamUrl } from './api';
import type { ProgressEvent } from './types';

export interface ScanStreamState {
  status: 'idle' | 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  lastModule?: string;
  overall?: number;
  grade?: string;
  error?: string;
  log: ProgressEvent[];
}

/**
 * Subscribe to a scan's live progress WebSocket. Returns evolving state; when it
 * reaches 'completed' the caller fetches the full report by scanId.
 */
export function useScanStream(scanId: string | null): ScanStreamState {
  const [state, setState] = useState<ScanStreamState>({ status: 'idle', progress: 0, log: [] });
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId) return;
    setState({ status: 'queued', progress: 0, log: [] });
    const ws = new WebSocket(scanStreamUrl(scanId));
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      // Wire messages are either ProgressEvents or an initial { type:'status', status } snapshot.
      let msg: { type: string; status?: string; module?: string; progress?: number; overall?: number; grade?: string; error?: string };
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      setState((s) => {
        const next: ScanStreamState = { ...s, log: [...s.log, msg as unknown as ProgressEvent] };
        // Initial status snapshot: the server sends this on connect. If the scan
        // already finished before the socket connected, this is the only message.
        if (msg.type === 'status') {
          const st = String(msg.status ?? '').toLowerCase();
          if (st === 'completed') {
            next.status = 'completed';
            next.progress = 1;
          } else if (st === 'failed') {
            next.status = 'failed';
          } else if (st === 'running') {
            next.status = 'running';
          }
        }
        if (msg.type === 'running') next.status = 'running';
        if (msg.type === 'module') {
          next.status = 'running';
          next.lastModule = msg.module;
          if (typeof msg.progress === 'number') next.progress = msg.progress;
        }
        if (msg.type === 'completed') {
          next.status = 'completed';
          next.progress = 1;
          next.overall = msg.overall;
          next.grade = msg.grade;
        }
        if (msg.type === 'failed') {
          next.status = 'failed';
          next.error = msg.error;
        }
        return next;
      });
    };
    ws.onerror = () => setState((s) => ({ ...s, error: s.error ?? 'connection error' }));

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [scanId]);

  return state;
}
