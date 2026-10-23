<script setup>
import { ref, computed } from 'vue';
import { state, runOp, loadLists, loadBlocklists, setRoute } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import ConfirmButton from '../components/ConfirmButton.vue';
import ToggleSwitch from '../components/ToggleSwitch.vue';
import {
  normalizeTld,
  normalizeKeyword,
  normalizeRegex,
  isHttpsUrl,
  MAX_BLOCKLIST_URLS,
  BLOCKLIST_ENTRY_LIMIT,
} from '../validate.js';

const FORMS = [
  {
    id: 'tlds',
    key: 'tld',
    title: 'Blocked TLDs',
    hint: 'Stops any query whose last label matches — the whole zone is off limits.',
    invalid: 'One label only, e.g. “zip”. Use a rule for “co.uk”.',
    placeholder: 'zip',
    empty: 'Add a suffix like “xyz” to start stopping queries.',
    addLabel: 'TLD',
    normalize: normalizeTld,
    on: () => state.settings?.tldBlock,
    kicker: 'TLD blocking is switched off in Settings.',
  },
  {
    id: 'keywords',
    key: 'keyword',
    title: 'Blocked keywords',
    hint: 'Stops a query when any label contains this text.',
    invalid: 'Lowercase letters, digits, dots and dashes only, at least 4 characters.',
    placeholder: 'doubleclick',
    empty: 'Add a fragment like “doubleclick” to start stopping queries.',
    addLabel: 'keyword',
    normalize: normalizeKeyword,
    on: () => state.settings?.keywordBlock,
    kicker: 'Keyword blocking is switched off in Settings.',
  },
  {
    id: 'regex',
    key: 'regex',
    title: 'Regex rules',
    hint: 'Stops any query whose name matches the pattern (matched against the full lowercase name).',
    invalid: 'A compileable pattern, 4–128 characters, no whitespace.',
    placeholder: 'cdn\\d+\\.example\\.com',
    empty: 'Add a pattern like “cdn\\d+\\.example\\.com” to start stopping queries.',
    addLabel: 'regex',
    normalize: normalizeRegex,
    engine: true, // the section header carries the on/off switch itself
  },
];

const draft = ref({ tld: '', keyword: '', regex: '' });
const blDraft = ref('');

const items = (id) => (id === 'tlds' ? state.tlds : id === 'regex' ? state.regex : state.keywords);
const typed = (form) => draft.value[form.key].trim();
// Same normalizer the API validates with, so a valid entry is always submittable.
const stored = (form) => form.normalize(typed(form));
const problem = (form) => (typed(form) && !stored(form) ? form.invalid : '');

async function add(form) {
  const value = stored(form);
  if (!value) return;
  try {
    await runOp(`lists.${form.key}.add`, {
      verb: `Add ${form.addLabel}`,
      ok: (r) => (r.added ? `${value} added` : `${value} was already on the list`),
      undo: async () => {
        await api.removeItem(form.id, value);
        await loadLists();
      },
      fn: async () => {
        const r = await api.addItem(form.id, value);
        await loadLists();
        return r;
      },
    });
    draft.value[form.key] = ''; // kept for fixing when the worker refuses
  } catch { /* the alert stack carries the reason */ }
}

async function remove(form, value) {
  await runOp(`lists.${form.key}.del:${value}`, {
    verb: 'Remove from list',
    ok: `${value} removed`,
    undo: async () => {
      await api.addItem(form.id, value);
      await loadLists();
    },
    fn: async () => {
      await api.removeItem(form.id, value);
      await loadLists();
      return value;
    },
  }).catch(() => {});
}

// ---- blocklist subscriptions ------------------------------------------------

const blocklist = computed(() => state.blocklist);
const subs = computed(() => blocklist.value?.subscriptions ?? []);
const blTotal = computed(() => blocklist.value?.total ?? 0);
const blMax = computed(() => blocklist.value?.maxUrls ?? MAX_BLOCKLIST_URLS);
const blLimit = computed(() => blocklist.value?.entryLimit ?? BLOCKLIST_ENTRY_LIMIT);
const atMax = computed(() => subs.value.length >= blMax.value);
const overLimit = computed(() => blTotal.value > blLimit.value);

const blProblem = computed(() => {
  const v = blDraft.value.trim();
  if (!v) return '';
  if (!isHttpsUrl(v)) return 'Needs an https:// URL — the worker fetches the list over https.';
  if (subs.value.some((s) => s.url === v)) return 'That blocklist is already subscribed.';
  return '';
});
const blCanAdd = computed(() => isHttpsUrl(blDraft.value.trim()) && !blProblem.value && !atMax.value);

async function addBlocklist() {
  const url = blDraft.value.trim();
  if (!blCanAdd.value) return;
  try {
    await runOp('lists.blocklist.add', {
      verb: 'Add blocklist',
      ok: (r) => `${r.subscriptions.length} subscription${r.subscriptions.length === 1 ? '' : 's'}`,
      undo: async () => {
        await api.removeBlocklist(url);
        await loadBlocklists();
      },
      fn: async () => {
        const r = await api.addBlocklist(url);
        await loadBlocklists();
        return r;
      },
    });
    blDraft.value = '';
  } catch { /* the alert stack carries the reason */ }
}

async function removeBlocklist(url) {
  await runOp(`lists.blocklist.del:${url}`, {
    verb: 'Remove blocklist',
    ok: 'Blocklist removed',
    undo: async () => {
      await api.addBlocklist(url);
      await loadBlocklists();
    },
    fn: async () => {
      await api.removeBlocklist(url);
      await loadBlocklists();
      return url;
    },
  }).catch(() => {});
}

async function reloadBlocklists() {
  await runOp('lists.blocklist.reload', {
    verb: 'Reload blocklists',
    ok: 'Blocklists reloaded',
    fn: async () => {
      await api.reloadBlocklists();
      await loadBlocklists();
    },
  }).catch(() => {});
}

// ---- regex engine toggle (mirrors Settings.toggle) -------------------------

async function toggleRegex(value) {
  const previous = state.settings.regexBlock;
  state.settings.regexBlock = value; // optimistic; reverted if the worker refuses
  try {
    await runOp('set.regexBlock', {
      verb: 'Save settings',
      ok: `Regex blocking ${value ? 'on' : 'off'}`,
      fn: () => api.saveSettings({ regexBlock: value }),
    });
  } catch {
    state.settings.regexBlock = previous;
  }
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-[21px] font-semibold tracking-tight">Filter lists</h1>
      <p class="hint mt-1">Remote blocklist subscriptions and three plain lists that decide on their own.</p>
    </div>

    <!-- Blocklist subscriptions: the worker holds these in memory -->
    <section class="panel overflow-hidden">
      <div class="px-5 py-4 border-b border-line flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 class="text-[15px] font-medium">Blocklist subscriptions</h2>
        <span class="st text-[12.5px] text-muted">
          {{ subs.length }}/{{ blMax }} listed
          <template v-if="blocklist?.totalExceptions">
            · {{ blocklist.totalExceptions.toLocaleString() }} exceptions
          </template>
        </span>
        <AppButton
          v-if="subs.length"
          small
          busy-key="lists.blocklist.reload"
          class="ml-auto"
          @click="reloadBlocklists"
        >
          Reload
        </AppButton>
      </div>

      <div class="px-5 py-4">
        <form class="flex flex-wrap items-center gap-2.5" @submit.prevent="addBlocklist">
          <input
            v-model="blDraft"
            @input="blDraft = $event.target.value"
            type="url"
            class="field flex-1 min-w-[220px] st"
            placeholder="https://raw.githubusercontent.com/…/domains"
            aria-label="Blocklist URL to subscribe"
            autocapitalize="none"
            spellcheck="false"
            :aria-invalid="Boolean(blProblem)"
          />
          <AppButton
            variant="solid"
            type="submit"
            busy-key="lists.blocklist.add"
            :disabled="!blCanAdd"
          >
            Add blocklist
          </AppButton>
        </form>

        <p class="hint mt-2.5" :class="blProblem && 'text-block'" aria-live="polite">
          {{ blProblem || 'Each subscription is fetched over https and merged in memory; the union answers every query.' }}
        </p>

        <div v-if="subs.length" class="mt-4 divide-y divide-line/70">
          <div
            v-for="s in subs"
            :key="s.url"
            class="py-3 flex flex-wrap items-baseline gap-x-3 gap-y-1"
          >
            <div class="min-w-0 flex-1">
              <span class="st text-[13px] break-all" :title="s.url">{{ s.url }}</span>
              <span
                v-if="s.source === 'deploy'"
                class="ml-2 st text-[11px] rounded border border-beacon/40 text-beacon px-1.5 py-0.5 align-middle"
                title="Comes from the BLOCKLIST_URL deployment variable — editable and deletable like any other."
              >
                default
              </span>
            </div>
            <div class="flex items-baseline gap-3 text-[12.5px] text-muted st">
              <span>{{ s.entries.toLocaleString() }} entries</span>
              <span v-if="s.exceptions">· {{ s.exceptions.toLocaleString() }} except.</span>
              <span
                v-if="s.error"
                class="text-block"
                :title="s.error"
              >
                · {{ s.error }}
              </span>
            </div>
            <ConfirmButton
              small
              label="Remove"
              armed-label="Confirm?"
              :busy-key="`lists.blocklist.del:${s.url}`"
              @confirm="removeBlocklist(s.url)"
            />
          </div>
        </div>

        <p v-else class="hint mt-3">
          No remote blocklist — every query goes to the upstream unless a rule or filter stops it.
        </p>
      </div>

      <div class="px-5 py-3 border-t border-line flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <p class="hint st">
          {{ blTotal.toLocaleString() }} entries held in memory
        </p>
        <p v-if="overLimit" class="st text-[12.5px] text-block" role="alert">
          More than {{ blLimit.toLocaleString() }} entries — the free plan can run the isolate out of memory.
        </p>
      </div>
    </section>

    <section
      v-for="form in FORMS"
      :key="form.id"
      class="panel overflow-hidden"
    >
      <div class="px-5 py-4 border-b border-line flex flex-wrap items-center gap-x-3 gap-y-1">
        <h2 class="text-[15px] font-medium">{{ form.title }}</h2>
        <span class="st text-[12.5px] text-muted">{{ items(form.id).length }} listed</span>
        <!-- Regex carries its own on/off switch in this header; the other two
             still point at Settings while their toggles live there. -->
        <ToggleSwitch
          v-if="form.engine && state.settings"
          class="ml-auto !py-0"
          :model-value="Boolean(state.settings.regexBlock)"
          label="Regex blocking"
          effect="Apply the patterns below to live queries."
          busy-key="set.regexBlock"
          @update:model-value="toggleRegex"
        />
        <button
          v-else-if="!form.on()"
          type="button"
          class="ml-auto text-[13px] text-beacon underline underline-offset-2"
          @click="setRoute('settings')"
        >
          {{ form.kicker }}
        </button>
      </div>

      <div class="px-5 py-4">
        <form class="flex flex-wrap items-center gap-2.5" @submit.prevent="add(form)">
          <!-- The plain @input mirror is deliberate: v-model's default handler
               ignores input events while an IME marks the text as composing
               (Gboard commits per word), so validity would not light up until
               blur or a non-letter keystroke ended the composition. -->
          <input
            v-model="draft[form.key]"
            @input="draft[form.key] = $event.target.value"
            type="text"
            class="field flex-1 min-w-[160px] st"
            :placeholder="form.placeholder"
            :aria-label="`New ${form.title} entry`"
            autocapitalize="none"
            spellcheck="false"
            :aria-invalid="Boolean(problem(form))"
          />
          <AppButton
            variant="solid"
            type="submit"
            :busy-key="`lists.${form.key}.add`"
            :disabled="!stored(form)"
          >
            Add
          </AppButton>
        </form>

        <p class="hint mt-2.5" :class="problem(form) && 'text-block'" aria-live="polite">
          {{ problem(form) || form.hint }}
        </p>

        <div v-if="items(form.id).length" class="mt-4 flex flex-wrap gap-2">
          <button
            v-for="item in items(form.id)"
            :key="item"
            type="button"
            class="group inline-flex items-center gap-1.5 rounded border border-line bg-raised pl-2.5 pr-1.5 h-7 st text-[12.5px] hover:border-block/60 transition-colors focus-visible:outline-2 focus-visible:outline-beacon"
            :disabled="state.ops[`lists.${form.key}.del:${item}`]"
            :aria-label="`Remove ${item} from ${form.title}`"
            @click="remove(form, item)"
          >
            <span v-if="state.ops[`lists.${form.key}.del:${item}`]" class="block w-2.5 h-2.5 rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
            {{ item }}
            <svg class="w-3 h-3 text-muted group-hover:text-block" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4.5 4.5l7 7M11.5 4.5l-7 7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" />
            </svg>
          </button>
        </div>

        <p v-else class="hint mt-3">
          Empty. {{ form.empty }}
        </p>
      </div>
    </section>
  </div>
</template>
