<script setup>
import { ref } from 'vue';
import { runOp } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import StatusPill from '../components/StatusPill.vue';

const domain = ref('');
const result = ref(null);
const history = ref([]);

async function probe() {
  const value = domain.value.trim();
  if (!value) return;
  result.value = null;
  await runOp('probe.run', {
    verb: 'Test domain',
    ok: (r) => `${r.domain} — ${r.status === 'none' || r.status === 'allow' ? 'let through' : 'stopped'}`,
    fn: async () => {
      const r = await api.probe(value);
      result.value = r;
      history.value = [r, ...history.value.filter((h) => h.domain !== r.domain)].slice(0, 5);
      return r;
    },
  }).catch(() => {});
}

const isBlocked = (r) => r && r.status !== 'none' && r.status !== 'allow';
const actionWord = (r) =>
  isBlocked(r) ? 'Stopped' : r && r.status === 'allow' ? 'Forced through' : 'Let through';
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
        />
        <AppButton variant="solid" type="submit" busy-key="probe.run" :disabled="!domain.trim()">
          Test domain
        </AppButton>
      </form>
      <p class="hint mt-2.5">Runs the full server-side pipeline: allow and deny rules first, then the blocklist and policies.</p>
    </section>

    <!-- Verdict -->
    <section
      v-if="result"
      class="panel p-5 rise-in border-l-4"
      :class="isBlocked(result) ? 'border-l-block' : 'border-l-pass'"
      aria-live="polite"
    >
      <div class="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span class="text-[19px] font-semibold tracking-tight" :class="isBlocked(result) ? 'text-block' : 'text-pass'">
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
        <div>
          <dt class="text-[12.5px] text-muted">Blocklist in memory</dt>
          <dd class="st text-[13.5px] mt-0.5">{{ result.blocklistSize.toLocaleString() }} entries</dd>
        </div>
        <div v-if="result.note">
          <dt class="text-[12.5px] text-muted">Still applies</dt>
          <dd class="hint mt-0.5">{{ result.note }}</dd>
        </div>
      </dl>
    </section>

    <!-- Recent probes -->
    <section v-if="history.length" class="panel divide-y divide-line/70">
      <div class="px-5 py-3">
        <h2 class="text-[15px] font-medium">Recent probes</h2>
      </div>
      <button
        v-for="h in history"
        :key="h.domain"
        type="button"
        class="w-full flex items-center gap-3 px-5 py-2.5 text-left hover:bg-raised transition-colors"
        @click="domain = h.domain, probe()"
      >
        <StatusPill :status="h.status" />
        <span class="st text-[13px] truncate flex-1">{{ h.domain }}</span>
        <span class="text-[12.5px] text-muted hidden sm:inline">{{ h.filter || 'no match' }}</span>
      </button>
    </section>

    <div v-else class="hint">
      Nothing probed yet — try the domain you expect to be blocked.
    </div>
  </div>
</template>