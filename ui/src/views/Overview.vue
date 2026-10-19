<script setup>
import { computed } from 'vue';
import { state, runOp, loadStats, setRoute } from '../store.js';
import AppButton from '../components/AppButton.vue';

const BLOCKED = ['deny', 'blocklist', 'tld', 'keyword', 'rebind', 'idn'];

const stats = computed(() => state.stats);
const blockedTotal = computed(() =>
  (stats.value?.byStatus.rows || [])
    .filter((r) => BLOCKED.includes(r.status))
    .reduce((n, r) => n + r.n, 0)
);
const blockedShare = computed(() => {
  const total = stats.value?.byStatus.total || 0;
  return total ? Math.round((blockedTotal.value / total) * 100) : 0;
});

const byStatus = computed(() =>
  [...(stats.value?.byStatus.rows || [])].sort((a, b) => b.n - a.n)
);
const maxStatus = computed(() => Math.max(1, ...byStatus.value.map((r) => r.n)));
const peak = computed(() => Math.max(1, ...(stats.value?.last24h || [])));
const topBlocked = computed(() => stats.value?.topBlocked || []);

const counts = computed(() => ({
  rules: state.rules.length,
  keywords: state.keywords.length,
  tlds: state.tlds.length,
}));

// Only the on/off switches count here; logRetentionDays is a number and would
// otherwise sit in the denominator unmovable.
const switches = computed(() => Object.values(state.settings || {}).filter((v) => typeof v === 'boolean'));
const switchesOn = computed(() => switches.value.filter(Boolean).length);

async function refresh() {
  await runOp('overview.refresh', { verb: 'Refresh overview', ok: 'Overview up to date', fn: loadStats });
}
</script>

<template>
  <div class="space-y-7">
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-[21px] font-semibold tracking-tight">Overview</h1>
        <p class="hint mt-1">What this resolver has seen and what it stopped.</p>
      </div>
      <AppButton busy-key="overview.refresh" :disabled="state.statsError === 'no_d1'" @click="refresh">
        Refresh
      </AppButton>
    </div>

    <!-- Empty / unconfigured logging -->
    <div v-if="state.statsError === 'no_d1'" class="panel p-5 rise-in">
      <p class="text-[15px] font-medium">No query history is being kept</p>
      <p class="hint mt-1.5 max-w-prose">
        The worker has no <span class="st">LOGS</span> binding, so there is nothing to count yet.
        Create a D1 database, reference it in <span class="st">wrangler.toml</span>, and redeploy:
        counts below start filling in on the next query.
      </p>
      <AppButton variant="solid" class="mt-4" busy-key="overview.recheck" @click="runOp('overview.recheck', { verb: 'Check logging again', ok: 'Logging available', fn: loadStats }).catch(() => {})">
        Check again
      </AppButton>
    </div>

    <template v-else-if="stats">
      <!-- Counters -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div class="panel p-4">
          <p class="text-[12.5px] text-muted">Queries logged</p>
          <p class="st text-[26px] mt-1 leading-none">{{ stats.total.toLocaleString() }}</p>
        </div>
        <div class="panel p-4">
          <p class="text-[12.5px] text-muted">Stopped by policy</p>
          <p class="st text-[26px] mt-1 leading-none text-block">{{ blockedShare }}%</p>
          <p class="hint mt-1">{{ blockedTotal.toLocaleString() }} queries</p>
        </div>
        <div class="panel p-4">
          <p class="text-[12.5px] text-muted">Custom rules</p>
          <p class="st text-[26px] mt-1 leading-none">{{ counts.rules }}</p>
          <p class="hint mt-1">{{ counts.keywords }} keywords · {{ counts.tlds }} TLDs</p>
        </div>
        <div class="panel p-4">
          <p class="text-[12.5px] text-muted">Protections on</p>
          <p class="st text-[26px] mt-1 leading-none">{{ switchesOn }}</p>
          <p class="hint mt-1">of {{ switches.length }} switches</p>
        </div>
      </div>

      <!-- Volume instrument -->
      <section class="panel p-5">
        <div class="flex items-baseline justify-between gap-4 flex-wrap">
          <div>
            <h2 class="text-[15px] font-medium">Query volume by hour of day</h2>
            <p class="hint mt-0.5">Last 7 days, local time. Peak {{ peak }} queries in an hour.</p>
          </div>
          <span class="st text-[12.5px] text-muted">{{ stats.last24h.reduce((a, b) => a + b, 0) }} total</span>
        </div>

        <div class="mt-4 flex items-end gap-[3px] h-28" role="img" aria-label="Hourly query volume for the last seven days">
          <div
            v-for="(n, h) in stats.last24h"
            :key="h"
            class="flex-1 rounded-t transition-all duration-300"
            :class="n > 0 ? 'bg-beacon/85 hover:bg-beacon' : 'bg-line/60'"
            :style="{ height: Math.max(3, Math.round((n / peak) * 100)) + '%' }"
            :title="`${String(h).padStart(2, '0')}:00 — ${String(h).padStart(2, '0')}:59 · ${n} queries`"
          />
        </div>
        <div class="mt-2 flex justify-between st text-[11.5px] text-muted" aria-hidden="true">
          <span>00</span>
          <span>06</span>
          <span>12</span>
          <span>18</span>
          <span>23</span>
        </div>
      </section>

      <div class="grid lg:grid-cols-2 gap-4">
        <!-- Status mix -->
        <section class="panel p-5">
          <h2 class="text-[15px] font-medium">Verification outcomes</h2>
          <p class="hint mt-0.5">Share of logged queries by the filter that decided.</p>
          <ul class="mt-4 space-y-3">
            <li v-for="r in byStatus" :key="r.status">
              <div class="flex items-baseline justify-between gap-3 text-[13px]">
                <span class="st">{{ r.status }}</span>
                <span class="st text-muted">{{ r.n.toLocaleString() }}</span>
              </div>
              <div class="mt-1 h-2 rounded-full bg-raised overflow-hidden">
                <div
                  class="h-full rounded-full transition-all duration-500"
                  :class="BLOCKED.includes(r.status) ? 'bg-block' : 'bg-pass/70'"
                  :style="{ width: Math.max(2, (r.n / maxStatus) * 100) + '%' }"
                />
              </div>
            </li>
          </ul>
        </section>

        <!-- Top blocked -->
        <section class="panel p-5">
          <div class="flex items-baseline justify-between gap-3">
            <h2 class="text-[15px] font-medium">Most blocked domains</h2>
            <button type="button" class="text-[13px] text-muted hover:text-ink underline underline-offset-2" @click="setRoute('logs')">
              Open logs
            </button>
          </div>
          <ol class="mt-3">
            <li
              v-for="(r, i) in topBlocked"
              :key="r.domain"
              class="flex items-baseline gap-3 py-2 border-b border-line/70 last:border-0"
            >
              <span class="st text-[12px] text-muted w-6 tabular-nums">{{ String(i + 1).padStart(2, '0') }}</span>
              <span class="st text-[13px] truncate flex-1" :title="r.domain">{{ r.domain }}</span>
              <span class="st text-[13px] text-muted">{{ r.n.toLocaleString() }}</span>
            </li>
          </ol>
          <p v-if="!topBlocked.length" class="hint mt-3">Nothing blocked yet — this resolver is letting everything through.</p>
        </section>
      </div>

      <p class="hint">
        {{ counts.rules }} custom {{ counts.rules === 1 ? 'rule' : 'rules' }} on file —
        <button type="button" class="text-ink underline underline-offset-2" @click="setRoute('rules')">manage them</button>.
      </p>
    </template>

    <div v-else class="panel p-6 text-center text-muted text-[13px]">
      <span class="block w-5 h-5 mx-auto rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
      <p class="mt-3">Reading the audit log…</p>
    </div>
  </div>
</template>