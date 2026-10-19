<script setup>
import { ref, computed } from 'vue';
import { runOp } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import StatusPill from '../components/StatusPill.vue';
import { loadProbeHistory, rememberProbe, clearProbeHistory } from '../probeHistory.js';
import { normalizeDomain } from '../validate.js';

const domain = ref('');
const result = ref(null);
const history = ref(loadProbeHistory());

// The API runs the same normalizer and answers 400 for anything else, so the
// field refuses those values up front instead of spending a request on them.
const normalized = computed(() => normalizeDomain(domain.value.trim()));
const invalid = computed(() => Boolean(domain.value.trim()) && !normalized.value);

async function probe() {
  const value = normalized.value;
  if (!value) return;
  result.value = null;
  await runOp('probe.run', {
    verb: 'Test domain',
    ok: (r) => `${r.domain} — ${r.status === 'none' || r.status === 'allow' ? 'let through' : 'stopped'}`,
    fn: async () => {
      const r = await api.probe(value);
      result.value = r;
      history.value = rememberProbe(history.value, r);
      return r;
    },
  }).catch(() => {});
}

function reuse(value) {
  domain.value = value;
  probe();
}

function forget() {
  clearProbeHistory();
  history.value = [];
}

const isBlocked = (r) => r && !['none', 'allow', 'route'].includes(r.status);
const isRouted = (r) => r && r.status === 'route';
const actionWord = (r) =>
  isRouted(r) ? 'Answered locally' : isBlocked(r) ? 'Stopped' : r && r.status === 'allow' ? 'Forced through' : 'Let through';
const tone = (r) => (isBlocked(r) ? 'text-block border-l-block' : isRouted(r) ? 'text-beacon border-l-beacon' : 'text-pass border-l-pass');

/** @param {number} ts @returns {string} */
function ago(ts) {
  if (!ts) return '';
  const diff = Date.now() - ts;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} h ago`;
  return `${Math.floor(diff / 86_400_000)} d ago`;
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-[21px] font-semibold tracking-tight">Probe</h1>
      <p class="hint mt-1">Ask the worker what it would answer, before pointing a client at it.</p>
    </div>

    <section class="panel p-5">
      <form class="flex flex-col sm:flex-row gap-2.5" @submit.prevent="probe">
        <input
          v-model="domain"
          type="text"
          class="field flex-1 st"
          placeholder="sub.example.com"
          aria-label="Domain to test"
          autocapitalize="none"
          spellcheck="false"
          :aria-invalid="invalid"
          aria-describedby="probe-note"
        />
        <AppButton variant="solid" type="submit" busy-key="probe.run" :disabled="!normalized">
          Test domain
        </AppButton>
      </form>
      <p id="probe-note" class="hint mt-2.5" :class="invalid && 'text-block'" aria-live="polite">
        {{ invalid
          ? 'Needs a real domain, like sub.example.com.'
          : 'Runs the full server-side pipeline: allow and deny rules first, then the blocklist and policies.' }}
      </p>
    </section>

    <!-- Verdict -->
    <section
      v-if="result"
      class="panel p-5 rise-in border-l-4"
      :class="tone(result)"
      aria-live="polite"
    >
      <div class="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span class="text-[19px] font-semibold tracking-tight" :class="tone(result).split(' ')[0]">
          {{ actionWord(result) }}
        </span>
        <StatusPill :status="result.status" />
        <span class="st text-[13.5px] text-muted">{{ result.domain }}</span>
      </div>

      <dl class="mt-4 grid sm:grid-cols-2 gap-x-6 gap-y-3">
        <div v-if="result.matched">
          <dt class="text-[12.5px] text-muted">Matched</dt>
          <dd class="st text-[13.5px] mt-0.5 break-all">{{ result.matched }}</dd>
        </div>
        <div v-if="result.filter">
          <dt class="text-[12.5px] text-muted">Decided by</dt>
          <dd class="st text-[13.5px] mt-0.5">{{ result.filter }}</dd>
        </div>
        <div v-if="result.route">
          <dt class="text-[12.5px] text-muted">Answer served</dt>
          <dd class="st text-[13.5px] mt-0.5 break-all">
            {{ result.route.type.toUpperCase() }} · {{ result.route.value }}
            <span class="text-muted">({{ result.route.ttl }} s)</span>
          </dd>
        </div>
        <div>
          <dt class="text-[12.5px] text-muted">Blocklist in memory</dt>
          <dd class="st text-[13.5px] mt-0.5">{{ result.blocklistSize.toLocaleString() }} entries</dd>
        </div>
        <div v-if="result.note && !result.route">
          <dt class="text-[12.5px] text-muted">Still applies</dt>
          <dd class="hint mt-0.5">{{ result.note }}</dd>
        </div>
      </dl>
    </section>

    <!-- Recent probes, kept in this browser only -->
    <section v-if="history.length" class="panel divide-y divide-line/70">
      <div class="px-5 py-3 flex items-center gap-3">
        <h2 class="text-[15px] font-medium">Recent probes</h2>
        <button
          type="button"
          class="ml-auto text-[12.5px] text-muted hover:text-ink underline underline-offset-2"
          @click="forget"
        >
          Clear
        </button>
      </div>
      <button
        v-for="h in history"
        :key="h.domain"
        type="button"
        class="w-full flex items-center gap-3 px-5 py-2.5 text-left hover:bg-raised transition-colors"
        @click="reuse(h.domain)"
      >
        <StatusPill :status="h.status" />
        <span class="st text-[13px] truncate flex-1">{{ h.domain }}</span>
        <span class="text-[12px] text-muted whitespace-nowrap">{{ ago(h.ts) }}</span>
      </button>
    </section>

    <div v-else class="hint">
      Nothing probed yet — try the domain you expect to be blocked.
    </div>
  </div>
</template>