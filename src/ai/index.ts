/** Advisor factory: AnthropicAdvisor when ANTHROPIC_API_KEY is set, else LocalAdvisor. */

import { AnthropicAdvisor } from './anthropic.js';
import { LocalAdvisor } from './local.js';
import type { Advisor } from './types.js';

export function getAdvisor(): Advisor {
  const key = process.env.ANTHROPIC_API_KEY;
  return key ? new AnthropicAdvisor(key) : new LocalAdvisor();
}

export { generateTickets } from './tickets.js';
export type { AdvisorOutput, Ticket } from './types.js';
