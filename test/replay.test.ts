import { test } from 'node:test';
import assert from 'node:assert/strict';
import { replayFindings, type ReplayFetch } from '../src/core/replay.js';
import type { Finding } from '../src/core/types.js';

function f(partial: Partial<Finding> & Pick<Finding, 'module' | 'title'>): Finding {
  return {
    id: partial.id ?? `${partial.module}.x`,
    module: partial.module,
    category: partial.category ?? 'security',
    title: partial.title,
    severity: partial.severity ?? 'medium',
    status: partial.status ?? 'fail',
    risk: 'r', whyItMatters: 'w', technical: 't', businessImpact: 'b',
    probability: 'medium', remediation: 'fix', estimatedFixTime: '1h', references: [],
    ...partial,
  };
}

/** Build a fake fetch returning given headers/status/body. */
function fakeFetch(spec: { headers?: Record<string, string>; status?: number; body?: string }): ReplayFetch {
  return async () =>
    new Response(spec.body ?? '', {
      status: spec.status ?? 200,
      headers: spec.headers ?? {},
    });
}

test('missing-header finding reproduces → confidence confirmed', async () => {
  const finding = f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', location: { url: 'http://x/' } });
  const { findings, reproduced, contradicted } = await replayFindings([finding], fakeFetch({ headers: {} }), { targetOrigin: 'http://x' });
  assert.equal(reproduced, 1);
  assert.equal(contradicted, 0);
  assert.equal(findings[0]?.confidence, 'confirmed');
  assert.equal(findings[0]?.status, 'fail');
  assert.equal(findings[0]?.evidence?.replay, 'reproduced');
});

test('missing-header finding is contradicted when header is actually present → demoted to info', async () => {
  const finding = f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', location: { url: 'http://x/secure' } });
  const { findings, contradicted } = await replayFindings(
    [finding],
    fakeFetch({ headers: { 'content-security-policy': "default-src 'self'" } }),
    { targetOrigin: 'http://x' },
  );
  assert.equal(contradicted, 1);
  assert.equal(findings[0]?.status, 'info'); // no longer penalizes the score
  assert.equal(findings[0]?.confidence, 'tentative');
  assert.match(findings[0]?.title ?? '', /not reproduced on replay/);
  assert.equal(findings[0]?.evidence?.replay, 'not-reproduced');
});

test('nosniff verifier: correct header contradicts, wrong value reproduces', async () => {
  const mk = () => f({ module: 'zap', title: 'X-Content-Type-Options Header Missing', location: { url: 'http://x/' } });
  const ok = await replayFindings([mk()], fakeFetch({ headers: { 'x-content-type-options': 'nosniff' } }), { targetOrigin: 'http://x' });
  assert.equal(ok.contradicted, 1);
  const bad = await replayFindings([mk()], fakeFetch({ headers: {} }), { targetOrigin: 'http://x' });
  assert.equal(bad.reproduced, 1);
});

test('exposure finding reproduces on 200+body, contradicted on 404', async () => {
  const mk = () => f({ module: 'zap', title: 'Hidden File Found — .git/config', location: { url: 'http://x/.git/config' } });
  const live = await replayFindings([mk()], fakeFetch({ status: 200, body: '[core]\nrepositoryformatversion = 0' }), { targetOrigin: 'http://x' });
  assert.equal(live.reproduced, 1);
  const gone = await replayFindings([mk()], fakeFetch({ status: 404, body: 'not found' }), { targetOrigin: 'http://x' });
  assert.equal(gone.contradicted, 1);
  assert.equal(gone.findings[0]?.status, 'info');
});

test('injection findings are never auto-replayed (skipped, untouched)', async () => {
  let called = false;
  const spyFetch: ReplayFetch = async () => {
    called = true;
    return new Response('', { status: 200 });
  };
  const finding = f({ module: 'zap', title: 'SQL Injection', severity: 'high', location: { url: 'http://x/a', param: 'q' } });
  const { findings, skipped } = await replayFindings([finding], spyFetch, { targetOrigin: 'http://x' });
  assert.equal(skipped, 1);
  assert.equal(called, false, 'must not send a request for injection findings');
  assert.equal(findings[0]?.status, 'fail'); // untouched
  assert.equal(findings[0]?.evidence?.replay, 'not-replayed');
});

test('network error is inconclusive → finding left untouched', async () => {
  const boom: ReplayFetch = async () => {
    throw new Error('conn refused');
  };
  const finding = f({ module: 'zap', title: 'HSTS Header Not Set', location: { url: 'http://x/' } });
  const { findings, reproduced, contradicted, skipped } = await replayFindings([finding], boom, { targetOrigin: 'http://x' });
  assert.equal(reproduced, 0);
  assert.equal(contradicted, 0);
  assert.equal(skipped, 1);
  assert.equal(findings[0]?.status, 'fail');
  assert.equal(findings[0]?.evidence?.replay, 'inconclusive');
});

test('pass/info findings pass through without a request', async () => {
  let called = false;
  const spy: ReplayFetch = async () => { called = true; return new Response('', { status: 200 }); };
  const pass = f({ module: 'ssl', title: 'TLS ok', status: 'pass', severity: 'info' });
  const { findings } = await replayFindings([pass], spy, { targetOrigin: 'http://x' });
  assert.equal(called, false);
  assert.equal(findings[0]?.status, 'pass');
});
