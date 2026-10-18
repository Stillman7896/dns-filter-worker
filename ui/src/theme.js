import { ref } from 'vue';

// Follows the system by default, with light/dark overrides kept across reloads.
const KEY = 'dns-dash-theme';
const MODES = ['auto', 'light', 'dark'];

function stored() {
  try {
    const v = localStorage.getItem(KEY);
    return MODES.includes(v) ? v : 'auto';
  } catch {
    return 'auto';
  }
}

export const themeMode = ref(stored());
export const isDark = ref(false);

const mq = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)') : null;

function resolve() {
  return themeMode.value === 'dark' || (themeMode.value === 'auto' && Boolean(mq?.matches));
}

function apply() {
  const dark = resolve();
  isDark.value = dark;
  const root = document.documentElement;
  root.classList.toggle('dark', dark);
  // Native controls ride along with the resolved theme.
  root.style.colorScheme = dark ? 'dark' : 'light';
  const meta = document.querySelector('meta[name="theme-color"]:not([media])');
  if (meta) meta.setAttribute('content', dark ? '#0B1018' : '#EEF1F6');
}

// index.html paints the pre-hydration frame; this brings the reactive state and
// DOM in step as soon as the module evaluates.
apply();

export function setTheme(mode) {
  themeMode.value = mode;
  try { localStorage.setItem(KEY, mode); } catch { /* private mode */ }
  apply();
}

export function cycleTheme() {
  setTheme(MODES[(MODES.indexOf(themeMode.value) + 1) % MODES.length]);
}

export const THEME_LABEL = { auto: 'System', light: 'Light', dark: 'Dark' };
export const THEME_NEXT = { auto: 'next: light', light: 'next: dark', dark: 'next: system' };

mq?.addEventListener?.('change', () => {
  if (themeMode.value === 'auto') apply();
});