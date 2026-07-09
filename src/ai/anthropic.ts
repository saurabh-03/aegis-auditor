/**
 * Claude-powered advisor. Uses the Anthropic Messages API to write the
 * executive summary and prioritized actions from the findings; the checklist and
 * grouping are computed deterministically. Falls back to the local advisor on any
 * API/parse error so a scan never fails because of the AI layer.
 *
 * Enabled when ANTHROPIC_API_KEY is set. Model via AI_MODEL (default claude-sonnet-5).
 */

import type { AuditReport } from '../core/types.js';
import { actionableFindings, checklist, counts, groupFindings } from './shared.js';
import { LocalAdvisor } from './local.js';
import type { Advisor, AdvisorOutput } from './types.js';

const API_URL = 'https://api.anthropic.com/v1/messages';

export class AnthropicAdvisor implements Advisor {
  readonly provider = 'anthropic' as const;
  private model: string;
  private local = new LocalAdvisor();

  constructor(private apiKey: string, model = process.env.AI_MODEL ?? 'claude-sonnet-5') {
    this.model = model;
  }

  async advise(report: AuditReport): Promise<AdvisorOutput> {
    const c = counts(report);
    const top = actionableFindings(report)
      .slice(0, 15)
      .map((f) => ({
        title: f.title,
        severity: f.severity,
        category: f.category,
        risk: f.risk,
        businessImpact: f.businessImpact,
        remediation: f.remediation,
        estimatedFixTime: f.estimatedFixTime,
      }));

    const prompt =
      `You are a senior application-security consultant writing for a mixed audience of executives and engineers. ` +
      `Given this website audit, produce a JSON object with exactly two keys: "executiveSummary" (2-4 sentence management-level paragraph, no jargon) and "prioritizedActions" (array of 3-6 short, imperative remediation actions ordered by impact). ` +
      `Be specific and grounded ONLY in the findings provided; do not invent vulnerabilities. Return JSON only.\n\n` +
      `Target: ${report.target}\nScore: ${report.overall.score}/100 (${report.overall.grade})\n` +
      `Counts: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low; ${c.passed} passing.\n` +
      `Findings:\n${JSON.stringify(top, null, 2)}`;

    try {
      const res = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: 1024,
          messages: [{ role: 'user', content: prompt }],
        }),
      });
      if (!res.ok) throw new Error(`Anthropic API ${res.status}`);
      const data = (await res.json()) as { content?: Array<{ type: string; text?: string }> };
      const text = data.content?.find((b) => b.type === 'text')?.text ?? '';
      const parsed = extractJson(text);
      if (!parsed || typeof parsed.executiveSummary !== 'string' || !Array.isArray(parsed.prioritizedActions)) {
        throw new Error('Unparseable advisor response');
      }
      return {
        provider: 'anthropic',
        model: this.model,
        executiveSummary: parsed.executiveSummary,
        prioritizedActions: parsed.prioritizedActions.map(String),
        remediationChecklist: checklist(report),
        groups: groupFindings(report),
      };
    } catch {
      // Never let the AI layer break the report.
      const fallback = await this.local.advise(report);
      return { ...fallback, provider: 'local', model: `${this.model} (fell back to local)` };
    }
  }
}

function extractJson(text: string): { executiveSummary?: unknown; prioritizedActions?: unknown } | null {
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
}
