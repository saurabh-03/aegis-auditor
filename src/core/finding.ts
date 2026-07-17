/** Helpers for constructing well-formed {@link Finding} objects. */

import type {
  Category,
  Confidence,
  Finding,
  FindingLocation,
  FindingStatus,
  Probability,
  Severity,
} from './types.js';

export interface FindingInput {
  id: string;
  module: string;
  category: Category;
  title: string;
  severity: Severity;
  status: FindingStatus;
  risk: string;
  whyItMatters: string;
  technical: string;
  businessImpact: string;
  probability: Probability;
  remediation: string;
  estimatedFixTime: string;
  cve?: string[];
  cwe?: string[];
  owasp?: string[];
  confidence?: Confidence;
  location?: FindingLocation;
  requestResponse?: { request: string; response: string };
  exampleCode?: string;
  references?: string[];
  evidence?: Record<string, unknown>;
}

export function finding(input: FindingInput): Finding {
  return {
    references: [],
    ...input,
  };
}

/** A passing check (status = pass, severity = info). Keeps reports positive. */
export function pass(
  module: string,
  category: Category,
  id: string,
  title: string,
  detail: string,
  evidence?: Record<string, unknown>,
): Finding {
  return finding({
    id,
    module,
    category,
    title,
    severity: 'info',
    status: 'pass',
    risk: 'No risk identified for this check.',
    whyItMatters: detail,
    technical: detail,
    businessImpact: 'This control is correctly configured and reduces risk.',
    probability: 'low',
    remediation: 'No action required. Maintain current configuration.',
    estimatedFixTime: '0 minutes',
    references: [],
    ...(evidence ? { evidence } : {}),
  });
}
