<script setup>
import { ref, computed, onMounted, onBeforeUnmount, watch } from 'vue';
import { state, runOp, loadLogs, loadRules, logPages, setRoute } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import ConfirmButton from '../components/ConfirmButton.vue';
import RowMenu from '../components/RowMenu.vue';
import StatusPill from '../components/StatusPill.vue';
import { qtypeLabel } from '../qtype.js';

const STATUSES = ['', 'allow', 'deny', 'blocklist', 'tld', 'keyword', 'rebind', 'idn', 'none'];
const LIMITS = [25, 50, 100, 250];

const search = ref(state.logs.search);
const status = ref(state.logs.status);
const limit = ref(state.logs.limit);
let debounce = null;

const rows = computed(() => state.logs.rows);
const total = computed(() => state.logs.total);
const noD1 = computed(() => state.statsError === 'no_d1');
const activeFilter = computed(() => Boolean(state.logs.search || state.logs.status));

function currentQuery() {
  return { search: state.logs.search, status: state.logs.status, limit: state.logs.limit, offset: state.logs.offset };
}

// Search narrows as you type; status/limit changes react immediately.
watch(search, (v) => {
  clearTimeout(debounce);
  debounce = setTimeout(async () => {
    state.logs.search = v;
    state.logs.offset = 0;
    await runOp('logs.search', { verb: 'Search logs', ok: `Showing ${total.value} matches`, fn: loadLogs }).catch(() => {});
  }, 400);
});

watch(status, async (v) => {
  state.logs.status = v;
  state.logs.offset = 0;
  await runOp('logs.filter', { verb: 'Apply status filter', ok: `Filtered to ${total.value} rows`, fn: loadLogs }).catch(() => {});
});

watch(limit, async (v) => {
  state.logs.limit = v;
  state.logs.offset = 0;
  await loadLogs().catch(() => {});
});

onMounted(() => loadLogs().catch(() => {}));
onBeforeUnmount(() => clearTimeout(debounce));

async function refresh() {
  await runOp('logs.refresh', { verb: 'Reload logs', ok: `${total.value} rows loaded`, fn: loadLogs }).catch(() => {});
}

async function deleteFiltered() {
  await runOp('logs.deleteFiltered', {
    verb: 'Delete filtered logs',
    ok: `${total.value} rows deleted`,
    fn: async () => {
      await api.deleteLogs({ ...currentQuery(), clear: undefined });
      state.logs.offset = 0;
      await loadLogs();
    },
  }).catch(() => {});
}

async function clearAll() {
  await runOp('logs.clear', {
    verb: 'Clear all logs',
    ok: 'Log cleared',
    fn: async () => {
      await api.deleteLogs({ clear: 1 });
      state.logs.offset = 0;
      await loadLogs();
    },
  }).catch(() => {});
}

async function removeRow(row) {
  await runOp(`logs.del:${row.id}`, {
    verb: 'Delete row',
    ok: `${row.domain} entry deleted`,
    fn: async () => {
      await api.deleteLog(row.id);
      await loadLogs();
    },
  }).catch(() => {});
}

/** Write a custom rule for the row's domain, so the next query is decided early. */
async function setRule(row, kind) {
  await runOp(`logs.${kind === 'deny' ? 'block' : 'allow'}:${row.domain}`, {
    verb: kind === 'deny' ? 'Block domain' : 'Allow domain',
    ok: `${row.domain} ${kind === 'deny' ? 'now blocked' : 'now allowed'}`,
    undo: async () => {
      await api.deleteRule(row.domain);
      await loadRules();
    },
    fn: async () => {
      const r = await api.addRule(row.domain, kind);
      await loadRules();
      return r;
    },
  }).catch(() => {});
}

async function page(dir) {
  state.logs.offset = Math.max(0, state.logs.offset + dir * state.logs.limit);
  await loadLogs().catch(() => {});
  document.getElementById('log-heading')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function timeOf(ts) {
  const d = new Date(ts);
  const diff = Date.now() - ts;
  const rel = diff < 60_000 ? 'just now'
    : diff < 3_600_000 ? `${Math.floor(diff / 60_000)} min ago`
      : diff < 86_400_000 ? `${Math.floor(diff / 3_600_000)} h ago`
        : `${Math.floor(diff / 86_400_000)} d ago`;
  return {
    rel,
    full: d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' }),
  };
}
</script>

<template>
  <div class="space-y-5">
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 id="log-heading" class="text-[21px] font-semibold tracking-tight">Logs</h1>
        <p class="hint mt-1">
          {{ total.toLocaleString() }} {{ total === 1 ? 'entry' : 'entries' }}
          <template v-if="activeFilter"> matching this filter</template>
        </p>
      </div>
      <div class="flex items-center gap-2">
        <AppButton busy-key="logs.refresh" :disabled="noD1" @click="refresh">Reload</AppButton>
        <AppButton v-if="!noD1 && activeFilter" busy-key="logs.deleteFiltered" @click="deleteFiltered">
          Delete filtered
        </AppButton>
        <ConfirmButton
          v-if="!noD1 && rows.length"
          label="Clear all"
          armed-label="Really clear the log?"
          busy-key="logs.clear"
          @confirm="clearAll"
        />
      </div>
    </div>

    <!-- Filters -->
    <div class="panel flex flex-wrap items-center gap-2.5 p-3">
      <label class="flex-1 min-w-[180px]">
        <span class="sr-only">Search domain</span>
        <input v-model="search" type="search" class="field w-full st" placeholder="Search domain…" spellcheck="false" />
      </label>
      <label class="flex items-center gap-2">
        <span class="text-[12.5px] text-muted hidden sm:inline">Status</span>
        <select v-model="status" class="field st">
          <option v-for="s in STATUSES" :key="s" :value="s">{{ s || 'any' }}</option>
        </select>
      </label>
      <label class="flex items-center gap-2">
        <span class="text-[12.5px] text-muted hidden sm:inline">Rows</span>
        <select v-model="limit" class="field st">
          <option v-for="l in LIMITS" :key="l" :value="l">{{ l }}</option>
        </select>
      </label>
      <button
        v-if="activeFilter"
        type="button"
        class="text-[13px] text-muted hover:text-ink underline underline-offset-2 ml-auto"
        @click="search = '', status = ''"
      >
        Reset filter
      </button>
    </div>

    <!-- No logging -->
    <div v-if="noD1" class="panel p-6 text-center">
      <p class="text-[15px] font-medium">The audit log is switched off</p>
      <p class="hint mt-1.5 max-w-prose mx-auto">
        No <span class="st">LOGS</span> D1 database is bound to this worker, so queries are answered but not recorded.
        Bind one and redeploy; the list then fills from the next query onwards.
      </p>
      <AppButton variant="solid" class="mt-4" @click="setRoute('settings')">Open settings</AppButton>
    </div>

    <!-- Rows: a real table, labels stay visible, narrow screens scroll it -->
    <section v-else class="panel overflow-hidden">
      <div v-if="rows.length" class="overflow-x-auto">
        <table class="w-full min-w-[540px] border-collapse text-left">
          <caption class="sr-only">Recent DNS queries</caption>
          <thead class="text-[12.5px] text-muted border-b border-line">
            <tr>
              <th scope="col" class="px-4 sm:px-5 py-2 font-medium whitespace-nowrap">When</th>
              <th scope="col" class="px-3 py-2 font-medium">Domain</th>
              <th scope="col" class="px-3 py-2 font-medium whitespace-nowrap">Outcome</th>
              <th scope="col" class="px-3 py-2 font-medium whitespace-nowrap">Type</th>
              <th scope="col" class="px-4 sm:px-5 py-2 font-medium text-right"><span class="sr-only">Action</span></th>
            </tr>
          </thead>
          <tbody class="divide-y divide-line/70">
            <tr v-for="r in rows" :key="r.id" class="hover:bg-raised/60 transition-colors">
              <td class="px-4 sm:px-5 py-3 whitespace-nowrap st text-[12.5px] text-muted" :title="timeOf(r.ts).full">
                {{ timeOf(r.ts).rel }}
              </td>
              <td class="px-3 py-3 w-full min-w-0">
                <span class="st text-[13.5px] truncate block" :title="r.domain">{{ r.domain }}</span>
              </td>
              <td class="px-3 py-3 whitespace-nowrap">
                <StatusPill :status="r.status" />
              </td>
              <td class="px-3 py-3 whitespace-nowrap st text-[12.5px] text-muted">{{ qtypeLabel(r.qtype) }}</td>
              <td class="px-4 sm:px-5 py-3 text-right whitespace-nowrap">
                <RowMenu
                  :label="`Quick actions for ${r.domain}`"
                  :keys="[`logs.allow:${r.domain}`, `logs.block:${r.domain}`, `logs.del:${r.id}`]"
                  @allow="setRule(r, 'allow')"
                  @block="setRule(r, 'deny')"
                  @remove="removeRow(r)"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="!rows.length" class="px-5 py-10 text-center">
        <p class="text-[14px] font-medium">{{ activeFilter ? 'Nothing matches that filter.' : 'The log is empty.' }}</p>
        <p class="hint mt-1.5">
          {{ activeFilter ? 'Clear the filter to see everything recorded.' : 'Queries will appear here as clients use this resolver.' }}
        </p>
      </div>

      <!-- Pager -->
      <div v-if="total > rows.length" class="flex items-center gap-3 px-4 sm:px-5 py-3 border-t border-line">
        <AppButton small :disabled="state.logs.offset === 0" @click="page(-1)">Previous</AppButton>
        <span class="st text-[12.5px] text-muted mx-auto">
          {{ logPages.page }} / {{ logPages.pages }}
        </span>
        <AppButton small :disabled="state.logs.offset + state.logs.limit >= total" @click="page(1)">
          Next page
        </AppButton>
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