import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import unocss from 'unocss/vite';
import { presetWind3 } from 'unocss';
import { mockApi } from './mock/api.js';

// Source lives in ui/; the Worker serves the build output from assets/.
// In `vite dev` the /api/* routes are answered by ./mock/api.js so the
// interface can be developed and reviewed without a deploy.
export default defineConfig({
  root: import.meta.dirname,
  plugins: [
    {
      name: 'mock-api',
      configureServer(server) {
        server.middlewares.use((req, res, next) => mockApi(req, res, next));
      },
    },
    vue(),
    unocss({
      presets: [presetWind3({ preflight: 'on-demand', dark: 'class' })],
      theme: {
        colors: {
          canvas: 'var(--c-canvas)',
          surface: 'var(--c-surface)',
          raised: 'var(--c-raised)',
          line: 'var(--c-line)',
          ink: 'var(--c-ink)',
          muted: 'var(--c-muted)',
          beacon: 'var(--c-beacon)',
          pass: 'var(--c-pass)',
          block: 'var(--c-block)',
        },
        fontFamily: {
          sans: "'Instrument Sans', ui-sans-serif, system-ui, sans-serif",
          mono: "'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace",
        },
      },
      shortcuts: {
        btn:
          "inline-flex items-center justify-center gap-1.5 rounded-md px-3 h-9 text-[13px] font-medium border transition-[transform,background-color,border-color,color] duration-150 disabled:opacity-50 disabled:pointer-events-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-beacon select-none relative",
        'btn-solid': 'bg-beacon text-black border-transparent hover:brightness-110 hover:-translate-y-px active:translate-y-0',
        'btn-ghost': 'bg-transparent text-ink border-line hover:border-muted hover:bg-raised',
        'btn-danger': 'bg-transparent text-block border-block/40 hover:bg-block hover:text-white hover:border-block',
        'btn-sm': 'h-8 px-2.5 text-[12.5px]',
        // 16px on phones: below that Safari auto-zooms on focus, and the fixed
        // box then clips the enlarged text. min-h keeps the control 36px tall
        // on both ends while the padding carries the phone font size.
        field:
          "min-h-9 rounded-md bg-raised border border-line px-2.5 py-1.5 text-[16px] text-ink placeholder-muted/70 focus:outline-none focus:border-beacon focus:ring-1 focus:ring-beacon/40 sm:py-0 sm:text-[13px]",
        area:
          "rounded-md bg-raised border border-line p-3 st text-[16px] leading-snug placeholder-muted/70 focus:outline-none focus:border-beacon focus:ring-1 focus:ring-beacon/40 sm:text-[13px]",
        label: 'block text-[13px] font-medium text-ink',
        hint: 'text-[12.5px] text-muted leading-snug',
        panel: 'rounded-lg border border-line bg-surface',
        'menu-item':
          'w-full flex items-center rounded px-2 h-8 text-[13px] text-left hover:bg-raised focus-visible:outline-2 focus-visible:outline-beacon transition-colors',
        st: 'font-mono font-medium tabular-nums',
        toster: 'text-[13px] leading-snug',
      },
    }),
  ],
  build: {
    outDir: '../assets',
    emptyOutDir: true,
    assetsDir: 'app',
    sourcemap: false,
  },
});