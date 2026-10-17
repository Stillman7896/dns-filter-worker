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

function apply() {
  const dark = themeMode.value === 'dark' || (themeMode.value === 'auto' && Boolean(mq?.matches));
  isDark.value = dark;
  document.documentElement.classList.toggle('dark', dark);
  const meta = document.querySelector('meta[name="theme-color"]:not([media])');
  if (meta) meta.setAttribute('content', dark ? '#0B1018' : '#EEF1F6');
}

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

mq?.addEventListener?.('change', () => themeMode.value === 'auto' && apply());