<script setup>
import { computed, ref } from 'vue';
import { state, runOp, loadStats, setRoute } from '../store.js';
import AppButton from '../components/AppButton.vue';
import CopyField from '../components/CopyField.vue';
import Modal from '../components/Modal.vue';
import Segmented from '../components/Segmented.vue';

const BLOCKED = ['deny', 'blocklist', 'tld', 'keyword', 'regex', 'rebind', 'idn'];

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
  routes: state.routes.length,
  keywords: state.keywords.length,
  regex: state.regex.length,
  tlds: state.tlds.length,
}));

// Only the on/off switches count here; logRetentionDays is a number and would
// otherwise be in the denominator unmovable.
const switches = computed(() => Object.values(state.settings || {}).filter((v) => typeof v === 'boolean'));
const switchesOn = computed(() => switches.value.filter(Boolean).length);

// ---- endpoint + setup guide ---------------------------------------------------

const endpoint = `${location.origin}/dns-query`;
const setupOpen = ref(false);
const guide = ref('browsers');

// Optional client tag: `/dns-query/<tag>` labels the client in the query log.
// Same rules the worker enforces (`?tag=` also works there).
const tag = ref('');
const TAG_RE = /^[a-z0-9](?:[a-z0-9_-]{0,62})$/;
const tagOk = computed(() => TAG_RE.test(tag.value.trim().toLowerCase()));
const tagProblem = computed(() =>
  (tag.value.trim() && !tagOk.value) ? 'Letters, digits, dashes and underscores — e.g. “laptop”.' : ''
);
const taggedEndpoint = computed(() =>
  `${location.origin}/dns-query/${encodeURIComponent(tag.value.trim().toLowerCase())}`
);

const GUIDES = [
  {
    id: 'browsers',
    label: 'Browsers',
    lines: [
      'Firefox — Settings → Privacy & Security → DNS over HTTPS → Max Protection → Custom, then paste the endpoint.',
      'Chrome / Edge — Settings → Privacy and security → Security → Use secure DNS → With → Custom, then paste the endpoint.',
    ],
  },
  {
    id: 'router',
    label: 'Router',
    lines: [
      'AdGuard Home — Settings → DNS settings → Upstream DNS servers, add the endpoint, then Test upstreams.',
      'Pi-hole — run cloudflared against the endpoint and point Pi-hole at 127.0.0.1#5053.',
    ],
    snippet: 'cloudflared proxy-dns --upstream {endpoint} --port 5053',
  },
  {
    id: 'mobile',
    label: 'Mobile',
    lines: [
      'Android — Private DNS only speaks DoT, so use a DoH client app and point it at the endpoint.',
      'iOS / macOS — install a DoH configuration profile or use a DoH client app; both just need the endpoint.',
    ],
  },
  {
    id: 'curl',
    label: 'curl',
    lines: ['query.bin is a raw DNS message; the response is one too.'],
    snippet: "curl -sS -H 'content-type: application/dns-message' \\\n  --data-binary @query.bin {endpoint} | xxd",
  },
];

const currentGuide = computed(() => GUIDES.find((g) => g.id === guide.value) || GUIDES[0]);
const snippet = computed(() => (currentGuide.value.snippet || '').replaceAll('{endpoint}', endpoint));

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

    <!-- Endpoint: the one thing every client needs -->
    <section class="panel p-5">
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 class="text-[15px] font-medium">Connect a client</h2>
          <p class="hint mt-0.5">Any DoH client pointed at this endpoint is filtered — no agent, no extra deploy.</p>
        </div>
        <AppButton small variant="solid" @click="setupOpen = true">Setup guide</AppButton>
      </div>

      <div class="mt-4">
        <CopyField :value="endpoint" label="DNS over HTTPS endpoint" />
      </div>

      <!-- Tag builder: one URL per device, so the log shows who asked -->
      <div class="mt-3 flex flex-col gap-1.5">
        <input
          v-model="tag"
          @input="tag = $event.target.value"
          type="text"
          class="field st sm:w-64"
          placeholder="per-client tag, e.g. laptop"
          aria-label="Client tag for the DoH URL"
          autocapitalize="none"
          spellcheck="false"
          :aria-invalid="Boolean(tagProblem)"
          maxlength="63"
        />
        <CopyField
          v-if="tagOk"
          :value="taggedEndpoint"
          label="Tagged DoH endpoint"
        />
        <p class="hint" :class="tagProblem && 'text-block'" aria-live="polite">
          {{ tagProblem || 'Optional: copy the tagged URL instead and every query from that device is labelled on the Logs page, where the Client filter can show it alone.' }}
        </p>
      </div>

      <div class="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1">
        <p class="hint">
          Upstream: <span class="st text-ink">{{ state.upstream?.label || '—' }}</span> ·
          <button type="button" class="underline underline-offset-2 text-muted hover:text-ink" @click="setRoute('settings')">
            change
          </button>
        </p>
        <p class="hint">
          {{ counts.routes }} {{ counts.routes === 1 ? 'route answers locally' : 'routes answer locally' }}
        </p>
      </div>
    </section>

    <Modal :open="setupOpen" title="Point a client at this resolver" @close="setupOpen = false">
      <CopyField :value="endpoint" label="DNS over HTTPS endpoint" />
      <CopyField
        v-if="tagOk"
        class="mt-2.5"
        :value="taggedEndpoint"
        label="Tagged DoH endpoint"
      />
      <p v-if="tagOk" class="hint mt-2">
        The tagged URL works in every guide below; queries logged through it carry the
        <span class="st">{{ tag.trim().toLowerCase() }}</span> client tag.
      </p>

      <div class="mt-4">
        <Segmented
          v-model="guide"
          :options="GUIDES.map((g) => ({ value: g.id, label: g.label }))"
          label="Client type"
        />
      </div>

      <ul class="mt-3.5 space-y-2">
        <li v-for="line in currentGuide.lines" :key="line" class="flex gap-2.5 text-[13px] leading-relaxed">
          <span class="mt-1.5 w-1 h-1 shrink-0 rounded-full bg-beacon" aria-hidden="true" />
          <span>{{ line }}</span>
        </li>
      </ul>

      <div v-if="snippet" class="mt-3.5">
        <CopyField :value="snippet" label="Command" />
      </div>

      <p class="hint mt-3.5">
        Filtering runs before the answer is cached, so blocked names stay blocked for every client using this
        endpoint. The endpoint requires no credentials — put it behind Cloudflare Access if it must stay private.
      </p>

      <template #footer>
        <div class="flex items-center justify-between gap-3">
          <span class="hint">DoH only — plain port 53 is not served by this worker.</span>
          <AppButton small @click="setupOpen = false">Done</AppButton>
        </div>
      </template>
    </Modal>

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
          <p class="hint mt-1">{{ counts.routes }} routes · {{ counts.keywords }} keywords · {{ counts.tlds }} TLDs</p>
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
                  :class="BLOCKED.includes(r.status) ? 'bg-block' : r.status === 'route' ? 'bg-beacon' : 'bg-pass/70'"
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
