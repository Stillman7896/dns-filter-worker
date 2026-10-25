<script setup>
import { computed } from 'vue';
import { state, VIEWS, setRoute, initStore, signOut, pendingCount, boot, runOp } from './store.js';
import { ApiError } from './api.js';
import { themeMode, cycleTheme, THEME_LABEL, THEME_NEXT } from './theme.js';
import ToastHost from './components/ToastHost.vue';
import AppButton from './components/AppButton.vue';
import Login from './views/Login.vue';
import Overview from './views/Overview.vue';
import Rules from './views/Rules.vue';
import Probe from './views/Probe.vue';
import Logs from './views/Logs.vue';
import FilterLists from './views/FilterLists.vue';
import Settings from './views/Settings.vue';
import Backup from './views/Backup.vue';

const PAGES = {
  overview: Overview,
  rules: Rules,
  probe: Probe,
  logs: Logs,
  lists: FilterLists,
  settings: Settings,
  backup: Backup,
};

const page = computed(() => PAGES[state.route] || Overview);
const groups = [
  { id: 'traffic', label: 'Live traffic', items: VIEWS.filter((v) => v.group === 'traffic') },
  { id: 'config', label: 'Configuration', items: VIEWS.filter((v) => v.group === 'config') },
];

const THEME_ICON = {
  auto: 'M4 6.5h16v8H4zM8.5 18h7',
  light: 'M12 4v2M12 18v2M4 12h2M18 12h2M6.3 6.3l1.4 1.4M16.3 16.3l1.4 1.4M17.7 6.3l-1.4 1.4M7.7 16.3l-1.4 1.4',
  dark: 'M15.5 4.5A7.5 7.5 0 1 0 19.5 15 6 6 0 0 1 15.5 4.5z',
};

initStore();

const ORIGIN = location.origin;

/** Re-run boot() and report the real outcome — boot() itself never throws. */
async function retryBoot() {
  await runOp('boot.retry', {
    verb: 'Reconnect',
    ok: 'Worker answered',
    fn: async () => {
      await boot();
      if (state.phase !== 'boot') return state.phase;
      throw new ApiError(state.bootError || 'the worker did not answer.');
    },
  }).catch(() => {});
}
</script>

<template>
  <div class="min-h-dvh flex flex-col">
    <header class="sticky top-0 z-40 bg-canvas/92 backdrop-blur-sm border-b border-line">
      <div class="w-full max-w-6xl mx-auto flex items-center gap-3 px-4 sm:px-6 md:px-8 h-14">
        <a href="#/overview" class="flex items-center gap-2.5 group" aria-label="Sinkker control">
          <!-- brand/mark.svg, inline so it can inherit the beacon colour -->
          <svg class="w-[26px] h-[26px] text-beacon" viewBox="0 0 32 32" fill="none" aria-hidden="true">
            <g stroke="currentColor" stroke-width="3" stroke-linecap="round">
              <path d="M5 5.5h22" />
              <path d="M9.5 12.5h13" opacity="0.72" />
              <path d="M12.5 19.5h7" opacity="0.5" />
            </g>
            <circle cx="16" cy="25.6" r="2.6" fill="currentColor" />
          </svg>
          <span class="flex items-baseline gap-2">
            <span class="text-[15px] font-semibold tracking-tight">Sinkker</span>
            <span class="hidden sm:inline text-[12.5px] text-muted">DNS sinkhole</span>
          </span>
        </a>

        <div class="ml-auto flex items-center gap-2">
          <span
            v-if="pendingCount"
            class="hidden sm:inline-flex items-center gap-1.5 text-[12.5px] text-muted"
            role="status"
          >
            <span class="block w-3 h-3 rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
            {{ pendingCount }} running
          </span>

          <button
            type="button"
            class="btn btn-sm"
            :title="`Theme: ${THEME_LABEL[themeMode]} — ${THEME_NEXT[themeMode]}`"
            :aria-label="`Theme: ${THEME_LABEL[themeMode]}. Activate for ${THEME_NEXT[themeMode].replace('next: ', '')}.`"
            @click="cycleTheme"
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" aria-hidden="true">
              <path :d="THEME_ICON[themeMode]" />
              <circle v-if="themeMode === 'light'" cx="12" cy="12" r="3.4" />
            </svg>
            <span class="hidden sm:inline">{{ THEME_LABEL[themeMode] }}</span>
          </button>

          <button v-if="state.phase === 'ready'" type="button" class="btn btn-sm" @click="signOut">Sign out</button>
        </div>
      </div>

      <!-- Mobile / tablet nav: a scrollable switch strip under the bar -->
      <nav class="md:hidden overflow-x-auto border-t border-line" aria-label="Sections">
        <div class="flex gap-1 px-2 py-1.5 w-max">
          <button
            v-for="v in VIEWS"
            :key="v.id"
            type="button"
            :aria-current="state.route === v.id ? 'page' : undefined"
            class="h-8 px-3 rounded text-[13px] font-medium whitespace-nowrap transition-colors duration-150"
            :class="state.route === v.id ? 'bg-beacon text-black' : 'text-muted'"
            @click="setRoute(v.id)"
          >
            {{ v.label }}
          </button>
        </div>
      </nav>
    </header>

    <div class="w-full max-w-6xl mx-auto flex flex-1 w-full">
      <!-- Desktop rail -->
      <aside class="hidden md:block w-56 shrink-0 border-r border-line">
        <div class="sticky top-14 py-6 pr-4 pl-6 md:pl-8 space-y-5">
          <div v-for="g in groups" :key="g.id">
            <p class="text-[12.5px] text-muted mb-2">{{ g.label }}</p>
            <nav class="flex flex-col gap-1" :aria-label="g.label">
              <button
                v-for="v in g.items"
                :key="v.id"
                type="button"
                :title="v.verb"
                :aria-current="state.route === v.id ? 'page' : undefined"
                class="group flex items-center gap-2 h-9 pl-3 pr-2 rounded-md text-[13.5px] text-left transition-colors duration-150 border-l-2"
                :class="state.route === v.id
                  ? 'border-beacon bg-raised text-ink font-medium'
                  : 'border-transparent text-muted hover:text-ink hover:bg-raised'"
                @click="setRoute(v.id)"
              >
                {{ v.label }}
              </button>
            </nav>
          </div>
        </div>
      </aside>

      <main class="flex-1 min-w-0 px-4 sm:px-6 md:pl-6 md:pr-8 py-6 pb-28 sm:pb-16">
        <Login v-if="state.phase !== 'ready' && state.phase !== 'boot'" />
        <template v-else-if="state.phase === 'ready'">
          <component :is="page" :key="state.route" />
        </template>
        <template v-else-if="state.phase === 'boot' && state.bootError">
          <div class="max-w-2xl mx-auto pt-6 rise-in">
            <div class="panel shadow-[var(--shadow-card)] p-6 sm:p-7">
              <h1 class="text-[19px] font-semibold tracking-tight">The worker did not answer</h1>
              <p class="hint mt-2 leading-relaxed">{{ state.bootError }}</p>

              <p class="hint mt-4 leading-relaxed">
                If its own configuration did this — too many blocklists, one giant list, past the
                free plan's CPU or memory budget — every request dies together, including
                <span class="st">/api/*</span>. The reset hatch sits beside
                <span class="st">/healthz</span> and runs before any blocklist or store work, so it
                still answers:
              </p>
              <div class="mt-3 rounded-md border border-line bg-raised px-3 py-2.5 st text-[12.5px] leading-relaxed overflow-x-auto">
                <div class="text-beacon">curl -X POST {{ ORIGIN }}/healthz/reset \</div>
                <div class="text-beacon pl-4">-H "Authorization: Bearer &lt;password&gt;"</div>
              </div>
              <p class="hint mt-3 leading-relaxed">
                Wipes settings, custom rules and filter lists; deployment variables and the query
                log stay. Needs <span class="st">DASHBOARD_PASSWORD</span> — the same password as
                the dashboard. (Documents over 400k entries / 24 MB are refused before parsing now,
                so this should not recur.)
              </p>

              <AppButton variant="solid" block class="mt-4" @click="retryBoot">
                Try again
              </AppButton>
            </div>
          </div>
        </template>
        <template v-else>
          <div class="h-40 grid place-items-center text-muted gap-3">
            <span class="block w-5 h-5 rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
            <p class="text-[13px]">Contacting the worker…</p>
          </div>
        </template>
      </main>
    </div>

    <ToastHost />
  </div>
</template>