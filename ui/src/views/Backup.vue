<script setup>
import { ref, computed } from 'vue';
import { state, runOp, loadRules, loadRoutes, loadLists, pushError } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import ConfirmButton from '../components/ConfirmButton.vue';
import Segmented from '../components/Segmented.vue';

const fileInput = ref(null);
const payload = ref(null);
const mode = ref('merge');
const fileName = ref('');

const lines = (v) => (Array.isArray(v) ? v.length : 0);
const summary = computed(() => {
  const p = payload.value;
  if (!p) return null;
  return {
    rules: lines(p.rules),
    routes: lines(p.routes),
    keywords: lines(p.keywords),
    regex: lines(p.regex),
    tlds: lines(p.tlds),
    settings: p.settings && typeof p.settings === 'object',
  };
});
const canImport = computed(() => Boolean(summary.value) && Object.values(summary.value).some((v) => v));

async function exportConfig() {
  await runOp('backup.export', {
    verb: 'Export config',
    ok: (p) => `${lines(p.rules)} rules, ${lines(p.routes)} routes, ${lines(p.keywords)} keywords, ${lines(p.regex)} regex, ${lines(p.tlds)} TLDs exported`,
    fn: async () => {
      const data = await api.exportConfig();
      const stamp = new Date().toISOString().slice(0, 10);
      const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `sinkker-${stamp}.json`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 4000);
      return data;
    },
  }).catch(() => {});
}

async function pickFile(e) {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  fileName.value = f.name;
  payload.value = null;
  const text = await f.text().catch(() => null);
  try {
    payload.value = JSON.parse(text);
  } catch {
    pushError('That file is not JSON', 'Export a config from this page first, then pick that file.');
    reset();
  }
}

/** Forget the picked file, and clear the input so the same file can be re-picked. */
function reset() {
  fileName.value = '';
  payload.value = null;
  if (fileInput.value) fileInput.value.value = '';
}

async function importConfig() {
  try {
    await runOp('backup.import', {
      verb: 'Import config',
      ok: (r) => `${mode.value === 'replace' ? 'Configuration replaced' : 'Configuration merged'}${
        r.rules ? ` · ${r.rules.applied} rules` : '' }`,
      fn: async () => {
        const r = await api.importConfig({ ...payload.value, mode: mode.value });
        await Promise.all([loadRules(), loadRoutes(), loadLists()]);
        state.settings = (await api.getSettings()).settings;
        return r;
      },
    });
  } catch { /* the file stays picked so it can be sent again */ return; }
  reset();
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-[21px] font-semibold tracking-tight">Backup</h1>
      <p class="hint mt-1">One JSON file holds every change you have made here: settings, rules, routes, keywords, regex, TLDs.</p>
    </div>

    <section class="panel p-5">
      <h2 class="text-[15px] font-medium">Take a copy</h2>
      <p class="hint mt-1">Downloaded straight from the worker, so it matches what is live now.</p>
      <AppButton variant="solid" class="mt-4" busy-key="backup.export" @click="exportConfig">
        Download config
      </AppButton>
    </section>

    <section class="panel p-5">
      <h2 class="text-[15px] font-medium">Bring a config back</h2>
      <p class="hint mt-1">Merge adds to what is there; replace wipes the current lists first.</p>

      <div class="mt-4 flex flex-wrap items-center gap-3">
        <label class="btn btn-ghost cursor-pointer">
          <input
            ref="fileInput"
            type="file"
            accept="application/json,.json"
            class="sr-only"
            aria-label="Choose a config file"
            @change="pickFile"
          />
          Choose file
        </label>
        <span class="st text-[13px] text-muted truncate max-w-full">{{ fileName || 'No file chosen' }}</span>
        <button v-if="fileName" type="button" class="text-[13px] text-muted hover:text-ink underline underline-offset-2 ml-auto" @click="reset">
          Clear
        </button>
      </div>

      <div v-if="summary" class="mt-4 rounded-md border border-line bg-raised p-3.5 space-y-2 rise-in">
        <div class="flex justify-between gap-4 text-[13px]">
          <span class="st">rules</span><span class="st text-muted">{{ summary.rules }}</span>
        </div>
        <div class="flex justify-between gap-4 text-[13px]">
          <span class="st">routes</span><span class="st text-muted">{{ summary.routes }}</span>
        </div>
        <div class="flex justify-between gap-4 text-[13px]">
          <span class="st">keywords</span><span class="st text-muted">{{ summary.keywords }}</span>
        </div>
        <div class="flex justify-between gap-4 text-[13px]">
          <span class="st">regex</span><span class="st text-muted">{{ summary.regex }}</span>
        </div>
        <div class="flex justify-between gap-4 text-[13px]">
          <span class="st">tlds</span><span class="st text-muted">{{ summary.tlds }}</span>
        </div>
        <div class="flex justify-between gap-4 text-[13px]">
          <span class="st">settings</span><span class="st text-muted">{{ summary.settings ? 'included' : 'none' }}</span>
        </div>
        <p v-if="!canImport" class="hint text-block">Nothing in this file can be imported.</p>
      </div>

      <div v-if="summary && canImport" class="mt-4 flex flex-wrap items-center gap-3">
        <Segmented
          v-model="mode"
          :options="[
            { value: 'merge', label: 'Merge' },
            { value: 'replace', label: 'Replace' },
          ]"
          label="Mode"
        />
        <ConfirmButton
          v-if="mode === 'replace'"
          label="Replace everything"
          armed-label="Confirm: overwrite lists"
          busy-key="backup.import"
          @confirm="importConfig"
        />
        <AppButton v-else variant="solid" busy-key="backup.import" @click="importConfig">
          Import this file
        </AppButton>
        <span class="hint">{{ mode === 'replace' ? 'A replace cannot be undone — export first.' : 'Existing entries are kept.' }}</span>
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