<script setup>
import { ref, computed } from 'vue';
import { state, runOp, loadRules, filteredRules } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import ConfirmButton from '../components/ConfirmButton.vue';
import Segmented from '../components/Segmented.vue';
import { normalizeDomain } from '../validate.js';

const domain = ref('');
const kind = ref('deny');
const ruleFilter = ref('');
const bulkKind = ref('deny');
const bulkText = ref('');
const showBulk = ref(false);

// What the worker will store for the typed value, or '' when it would reject
// it. Same function the API validates with, so the field can't disagree
// (URLs, wildcards and trailing dots are accepted; a bare word is not).
const normalized = computed(() => normalizeDomain(domain.value.trim()));
const invalid = computed(() => Boolean(domain.value.trim()) && !normalized.value);
const note = computed(() => {
  if (invalid.value) return 'Needs a real domain, like ads.example.net.';
  if (normalized.value && normalized.value !== domain.value.trim()) return `Saves as ${normalized.value}.`;
  return 'A rule applies to the domain and every subdomain of it. Allow wins over the blocklist.';
});

async function addRule() {
  const value = normalized.value;
  if (!value) return;
  try {
    await runOp('rules.add', {
      verb: 'Add rule',
      ok: (r) => `${r.domain} ${r.kind === 'deny' ? 'now blocked' : 'now allowed'}`,
      undo: async (r) => {
        await api.deleteRule(r.domain);
        await loadRules();
      },
      fn: async () => {
        const r = await api.addRule(value, kind.value);
        await loadRules();
        return r;
      },
    });
    domain.value = ''; // keep the text so it can be fixed and resent on failure
  } catch { /* the alert stack carries the reason */ }
}

async function importBulk() {
  if (!bulkReady.value) return;
  const text = bulkText.value.trim();
  await runOp('rules.bulk', {
    verb: 'Import rules',
    ok: (r) => (r.skipped.length
      ? `${r.added} added, ${r.skipped.length} left out`
      : `${r.added} rules added`),
    fn: async () => {
      const r = await api.bulkRules(bulkKind.value, text);
      await loadRules();
      if (!r.skipped.length) bulkText.value = '';
      return r;
    },
  }).catch(() => {});
}

// The worker splits on newlines/commas and drops whatever isn't a domain, so
// count the same way and say up front how many lines will actually land.
const bulkLines = computed(() => bulkText.value.split(/[\r\n,]+/).map((l) => l.trim()).filter(Boolean));
const bulkReady = computed(() => bulkLines.value.filter((l) => normalizeDomain(l)).length);

async function removeRule(r) {
  await runOp(`rules.del:${r.domain}`, {
    verb: 'Remove rule',
    ok: () => `${r.domain} removed`,
    undo: async (res) => {
      await api.addRule(res.domain, res.kind);
      await loadRules();
    },
    fn: async () => {
      await api.deleteRule(r.domain);
      await loadRules();
      return { domain: r.domain, kind: r.kind };
    },
  }).catch(() => {});
}

function onFilter(e) {
  ruleFilter.value = e.target.value;
  state.ruleFilter = e.target.value;
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-[21px] font-semibold tracking-tight">Rules</h1>
        <p class="hint mt-1">
          Custom answers run before the shared blocklist. {{ state.rules.length }}
          {{ state.rules.length === 1 ? 'rule' : 'rules' }} on file.
        </p>
      </div>
      <AppButton @click="showBulk = !showBulk">
        {{ showBulk ? 'Close bulk import' : 'Bulk import' }}
      </AppButton>
    </div>

    <!-- Add one -->
    <section class="panel p-5">
      <h2 class="text-[15px] font-medium">Add a rule</h2>
      <form class="mt-3 flex flex-col gap-2.5" @submit.prevent="addRule">
        <div class="flex flex-wrap items-center gap-2.5">
          <input
            v-model="domain"
            @input="domain = $event.target.value"
            type="text"
            class="field flex-1 min-w-[180px] st"
            placeholder="ads.example.net"
            aria-label="Domain"
            autocapitalize="none"
            spellcheck="false"
            :aria-invalid="invalid"
            aria-describedby="rule-note"
          />
          <Segmented
            v-model="kind"
            :options="[
              { value: 'deny', label: 'Block' },
              { value: 'allow', label: 'Allow' },
            ]"
            label="Answer"
          />
        </div>
        <AppButton
          variant="solid"
          type="submit"
          busy-key="rules.add"
          :disabled="!normalized"
          class="w-full sm:w-auto sm:self-start"
        >
          Add rule
        </AppButton>
      </form>
      <p id="rule-note" class="hint mt-2.5" :class="invalid && 'text-block'" aria-live="polite">
        {{ note }}
      </p>
    </section>

    <!-- Bulk -->
    <section v-if="showBulk" class="panel p-5 rise-in">
      <h2 class="text-[15px] font-medium">Paste many domains</h2>
      <p class="hint mt-1">One per line, or separated by commas.</p>
      <textarea
        v-model="bulkText"
        @input="bulkText = $event.target.value"
        rows="7"
        class="w-full mt-3 rounded-md bg-raised border border-line p-3 st text-[13px] focus:outline-none focus:border-beacon focus:ring-1 focus:ring-beacon/40"
        placeholder="ads.example.net&#10;beacon.partner.dev&#10;tracker.example.com"
        spellcheck="false"
        aria-label="Domains to import"
      />
      <div class="mt-3 flex flex-wrap items-center gap-2.5">
        <Segmented
          v-model="bulkKind"
          :options="[
            { value: 'deny', label: 'Block them' },
            { value: 'allow', label: 'Allow them' },
          ]"
          label="Kind"
        />
        <AppButton variant="solid" busy-key="rules.bulk" :disabled="!bulkReady" @click="importBulk">
          Import
        </AppButton>
        <span class="hint">
          {{ bulkReady }} of {{ bulkLines.length }} lines ready
          <template v-if="bulkLines.length && bulkReady < bulkLines.length">— the rest are not domains</template>
        </span>
      </div>
    </section>

    <!-- Rows: one row per rule, labels always visible -->
    <section class="panel overflow-hidden">
      <div class="flex flex-wrap items-center gap-3 px-4 sm:px-5 py-3.5 border-b border-line">
        <h2 class="text-[15px] font-medium">All rules</h2>
        <label class="ml-auto flex items-center gap-2">
          <span class="sr-only">Filter rules</span>
          <input
            type="text"
            class="field w-44 sm:w-56"
            placeholder="Filter…"
            :value="ruleFilter"
            @input="onFilter"
          />
        </label>
      </div>

      <div v-if="filteredRules.length" class="overflow-x-auto">
        <table class="w-full min-w-[420px] border-collapse text-left">
          <caption class="sr-only">Custom allow and deny rules</caption>
          <thead class="text-[12.5px] text-muted border-b border-line">
            <tr>
              <th scope="col" class="px-5 py-2 font-medium">Domain</th>
              <th scope="col" class="px-3 py-2 font-medium whitespace-nowrap">Answer</th>
              <th scope="col" class="px-5 py-2 font-medium text-right"><span class="sr-only">Action</span></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-line/70">
            <tr v-for="r in filteredRules" :key="r.domain" class="hover:bg-raised/60 transition-colors">
              <td class="px-5 py-3 w-full min-w-0">
                <span class="st text-[13.5px] truncate block" :title="r.domain">{{ r.domain }}</span>
              </td>
              <td class="px-3 py-3 whitespace-nowrap">
                <span
                  class="text-[12px] st rounded border px-2 py-0.5"
                  :class="r.kind === 'deny' ? 'text-block border-block/40' : 'text-pass border-pass/40'"
                >
                  {{ r.kind === 'deny' ? 'blocked' : 'allowed' }}
                </span>
              </td>
              <td class="px-5 py-3 text-right whitespace-nowrap">
                <ConfirmButton
                  small
                  label="Remove"
                  armed-label="Confirm?"
                  :busy-key="`rules.del:${r.domain}`"
                  @confirm="removeRule(r)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="!filteredRules.length" class="px-5 py-10 text-center">
        <p class="text-[14px] font-medium">
          {{ ruleFilter ? `No rule matches “${ruleFilter}”.` : 'No custom rules yet.' }}
        </p>
        <p class="hint mt-1.5">
          {{ ruleFilter
            ? 'Try part of the domain, without the top-level suffix.'
            : 'Add a domain above to force an answer, or force-allow one the shared blocklist stops.' }}
        </p>
      </div>
    </section>
  </div>
</template>

<style scoped>
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
}
</style>