import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)',
        elev: 'var(--bg-elev)',
        elev2: 'var(--bg-elev-2)',
        border: 'var(--border)',
        ink: 'var(--text)',
        dim: 'var(--text-dim)',
        mute: 'var(--text-mute)',
        accent: 'var(--accent)',
        accent2: 'var(--accent-2)',
        ok: 'var(--green)',
        warn: 'var(--yellow)',
        danger: 'var(--red)',
        high: 'var(--orange)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
