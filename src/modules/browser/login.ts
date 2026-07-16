/**
 * Automated form-login → session capture (optional Puppeteer).
 *
 * Drives a real browser to submit a login form and returns the resulting
 * session cookies, so a scan can authenticate from a username/password instead
 * of a hand-copied token. Same optional-dependency contract as the crawler:
 * Puppeteer is imported through a string specifier so the project builds without
 * it, and every failure path returns null (the scan degrades to unauthenticated
 * rather than failing).
 *
 * SECURITY: the password is used only to type into the login field. It is never
 * logged, never returned, and never stored — only the derived cookies leave this
 * function.
 */

import { config } from '../../core/config.js';
import { assertPublicHost } from '../../core/ssrf.js';
import type { FormLogin } from '../../core/types.js';

export interface CaptureOptions {
  timeoutMs: number;
  log?: (msg: string) => void;
}

/** Format Puppeteer cookie objects into a Cookie header value. */
export function formatCookies(cookies: Array<{ name: string; value: string }>): string {
  return cookies
    .filter((c) => c && c.name)
    .map((c) => `${c.name}=${c.value}`)
    .join('; ');
}

// Heuristic selectors used when the caller doesn't pin one.
const USERNAME_GUESS = 'input[type=email], input[name*=user i], input[name*=email i], input[id*=user i], input[id*=email i], input[type=text]';
const PASSWORD_GUESS = 'input[type=password]';
const SUBMIT_GUESS = 'button[type=submit], input[type=submit], button';

/**
 * Perform the login and return `{ cookies }` (a Cookie header value), or null if
 * the browser engine is unavailable or the login could not be completed.
 */
export async function captureSession(login: FormLogin, opts: CaptureOptions): Promise<{ cookies: string } | null> {
  const log = opts.log ?? (() => {});

  let loginUrl: URL;
  try {
    loginUrl = new URL(login.loginUrl);
  } catch {
    return null;
  }
  // SSRF guard: never let form-login reach an internal host.
  try {
    await assertPublicHost(loginUrl.hostname, opts.timeoutMs);
  } catch {
    log('Form-login target is not a public host — skipping.');
    return null;
  }

  const specifier: string = 'puppeteer';
  let puppeteer: any;
  try {
    const mod: any = await import(specifier);
    puppeteer = mod.default ?? mod;
  } catch {
    log('Form-login needs the browser engine (Puppeteer), which is not installed — skipping.');
    return null;
  }

  let browser: any;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
  } catch {
    return null;
  }

  try {
    const page = await browser.newPage();
    await page.setUserAgent(config.userAgent);
    await page.goto(loginUrl.toString(), { waitUntil: 'networkidle2', timeout: opts.timeoutMs });

    const userSel = login.usernameSelector || USERNAME_GUESS;
    const passSel = login.passwordSelector || PASSWORD_GUESS;

    const userField = await page.$(userSel);
    const passField = await page.$(passSel);
    if (!userField || !passField) {
      log('Form-login: could not locate the username/password fields — skipping.');
      return null;
    }
    await userField.type(login.username, { delay: 5 });
    await passField.type(login.password, { delay: 5 });

    // Submit and wait for the resulting navigation (best-effort).
    const submit = await page.$(login.submitSelector || SUBMIT_GUESS);
    const nav = page.waitForNavigation({ waitUntil: 'networkidle2', timeout: opts.timeoutMs }).catch(() => null);
    if (submit) {
      await submit.click().catch(() => {});
    } else {
      await passField.press('Enter').catch(() => {});
    }
    await nav;

    const cookies = await page.cookies();
    const header = formatCookies(cookies);
    if (!header) {
      log('Form-login completed but no session cookies were set.');
      return null;
    }
    log(`Form-login succeeded: captured ${cookies.length} cookie(s).`);
    return { cookies: header };
  } catch {
    log('Form-login failed (navigation/selector error) — continuing unauthenticated.');
    return null;
  } finally {
    try {
      await browser.close();
    } catch {
      /* ignore */
    }
  }
}
