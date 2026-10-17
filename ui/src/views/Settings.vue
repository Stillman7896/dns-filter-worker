<script setup>
import { ref, computed } from 'vue';
import { state, runOp, setRoute } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import ToggleSwitch from '../components/ToggleSwitch.vue';

const TOGGLES = [
  {
    key: 'rebindProtection',
    label: 'Answer rebinding guard',
    effect: 'Refuse answers that point at private or local addresses, and any query for an internal hostname.',
  },
  {
    key: 'idnBlock',
    label: 'Punycode (IDN) hosts',
    effect: 'Refuse every internationalised hostname, so no look-alike spelling can slip through.',
  },
  {
    key: 'tldBlock',
    label: 'Blocked TLD list',
    effect: 'Refuse the suffixes listed on the Filter lists page.',
    route: 'lists',
  },
  {
    key: 'keywordBlock',
    label: 'Blocked keywords',
    effect: 'Refuse any query whose labels contain a keyword from the Filter lists page.',
    route: 'lists',
  },
  {
    key: 'logPassed',
    label: 'Record allowed queries',
    effect: 'Keep a log row for answers that went through. Switch off to log only what was stopped.',
  },
];

const retention = ref(state.settings ? String(state.settings.logRetentionDays) : '30');
const retentionError = ref('');

const ready = computed(() => Boolean(state.settings));
const retentionValid = computed(() => Number.isInteger(Number(retention.value)) && Number(retention.value) >= 0 && Number(retention.value) <= 3650);

async function toggle(t, value) {
  const previous = state.settings[t.key];
  state.settings[t.key] = value; // optimistic; reverted if the worker refuses
  try {
    await runOp(`set.${t.key}`, {
      verb: 'Save settings',
      ok: `${t.label} ${value ? 'on' : 'off'}`,
      fn: () => api.saveSettings({ [t.key]: value }),
    });
  } catch {
    state.settings[t.key] = previous;
  }
}

async function saveRetention() {
  retentionError.value = '';
  if (!retentionValid.value) {
    retentionError.value = 'Enter a whole number of days between 0 and 3650.';
    return;
  }
  try {
    await runOp('set.retention', {
      verb: 'Save settings',
      ok: `Log kept ${Number(retention.value) === 0 ? 'forever' : `for ${retention.value} days`}`,
      fn: async () => {
        const r = await api.saveSettings({ logRetentionDays: Number(retention.value) });
        retention.value = String(r.settings.logRetentionDays);
        return r;
      },
    });
  } catch {
    retention.value = String(state.settings.logRetentionDays);
  }
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-[21px] font-semibold tracking-tight">Settings</h1>
      <p class="hint mt-1">Each change is written to KV as you make it — there is nothing else to save.</p>
    </div>

    <section v-if="ready" class="panel px-5 py-4">
      <h2 class="text-[15px] font-medium">Filters</h2>
      <div class="mt-1 divide-y divide-line/70" role="group" aria-label="Filter settings">
        <template v-for="t in TOGGLES" :key="t.key">
          <div class="flex items-start justify-between gap-4 py-3.5">
            <ToggleSwitch
              class="flex-1 !py-0"
              :model-value="state.settings[t.key]"
              :label="t.label"
              :effect="t.effect"
              :busy-key="`set.${t.key}`"
              @update:model-value="toggle(t, $event)"
            />
            <button
              v-if="t.route"
              type="button"
              class="shrink-0 mt-1 text-[13px] text-muted hover:text-ink underline underline-offset-2"
              @click="setRoute(t.route)"
            >
              Open list
            </button>
          </div>
        </template>
      </div>
    </section>

    <section v-if="ready" class="panel px-5 py-4">
      <h2 class="text-[15px] font-medium">Query log</h2>
      <p class="hint mt-1">Older rows are deleted by a scheduled job.</p>

      <div class="mt-4 flex flex-wrap items-end gap-3">
        <label class="flex flex-col gap-1.5">
          <span class="label">Keep rows for</span>
          <span class="flex items-center gap-2">
            <input
              v-model="retention"
              type="number"
              min="0"
              max="3650"
              step="1"
              class="field w-28 st"
              :aria-invalid="Boolean(retentionError)"
              :aria-describedby="retentionError ? 'ret-error' : 'ret-hint'"
              @input="retentionError = ''"
              @keyup.enter="saveRetention"
            />
            <span class="text-[13px] text-muted">days</span>
          </span>
        </label>

        <AppButton variant="solid" busy-key="set.retention" :disabled="!retentionValid" @click="saveRetention">
          Save retention
        </AppButton>

        <span class="hint" :class="retentionError ? 'text-block' : ''">
          {{ retentionError || (Number(retention) === 0 ? '0 keeps rows forever.' : `Drops on day ${Number(retention) + 1}.`) }}
        </span>
      </div>
    </section>

    <div v-else class="panel p-6 text-center text-muted text-[13px]">
      <span class="block w-5 h-5 mx-auto rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
      <p class="mt-3">Reading current settings…</p>
    </div>
  </div>
</template>