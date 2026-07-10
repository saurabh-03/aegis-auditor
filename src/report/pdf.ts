/**
 * HTML → PDF rendering via optional Puppeteer.
 *
 * Puppeteer is not a hard dependency (keeps the core install light). When it's
 * absent, {@link renderPdf} throws {@link PdfUnavailableError} so callers can
 * respond with a helpful message instead of failing opaquely.
 */

export class PdfUnavailableError extends Error {
  constructor() {
    super('PDF rendering requires Puppeteer. Install it with `npm run enable:browser`, or use the HTML report.');
    this.name = 'PdfUnavailableError';
  }
}

async function loadPuppeteer(): Promise<any | null> {
  // Indirect specifier so TypeScript does not require the dependency to be present.
  const name = 'puppeteer';
  try {
    const mod: any = await import(name);
    return mod.default ?? mod;
  } catch {
    return null;
  }
}

/** Render a full HTML document to a PDF buffer. Throws if Puppeteer is unavailable. */
export async function renderPdf(html: string): Promise<Buffer> {
  const puppeteer = await loadPuppeteer();
  if (!puppeteer) throw new PdfUnavailableError();

  const browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      margin: { top: '18mm', bottom: '18mm', left: '14mm', right: '14mm' },
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close();
  }
}

export async function pdfAvailable(): Promise<boolean> {
  return (await loadPuppeteer()) !== null;
}
