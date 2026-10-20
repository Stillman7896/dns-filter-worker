<script setup>
import { ref } from 'vue';
import { state, runOp, loadLists, setRoute } from '../store.js';
import { api } from '../api.js';
import AppButton from '../components/AppButton.vue';
import { normalizeTld, normalizeKeyword } from '../validate.js';

const FORMS = [
  {
    id: 'tlds',
    key: 'tld',
    title: 'Blocked TLDs',
    hint: 'Stops any query whose last label matches — the whole zone is off limits.',
    invalid: 'One label only, e.g. “zip”. Use a rule for “co.uk”.',
    placeholder: 'zip',
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
    normalize: normalizeKeyword,
    on: () => state.settings?.keywordBlock,
    kicker: 'Keyword blocking is switched off in Settings.',
  },
];

const draft = ref({ tld: '', keyword: '' });

const items = (id) => (id === 'tlds' ? state.tlds : state.keywords);
const typed = (form) => draft.value[form.key].trim();
// Same normalizer the API validates with, so a valid entry is always submittable.
const stored = (form) => form.normalize(typed(form));
const problem = (form) => (typed(form) && !stored(form) ? form.invalid : '');

async function add(form) {
  const value = stored(form);
  if (!value) return;
  try {
    await runOp(`lists.${form.key}.add`, {
      verb: `Add ${form.key === 'tld' ? 'TLD' : 'keyword'}`,
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
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-[21px] font-semibold tracking-tight">Filter lists</h1>
      <p class="hint mt-1">Two plain lists that decide on their own, independent of the shared blocklist.</p>
    </div>

    <section
      v-for="form in FORMS"
      :key="form.id"
      class="panel overflow-hidden"
    >
      <div class="px-5 py-4 border-b border-line flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 class="text-[15px] font-medium">{{ form.title }}</h2>
        <span class="st text-[12.5px] text-muted">{{ items(form.id).length }} listed</span>
        <button
          v-if="!form.on()"
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
          Empty. Add a {{ form.key === 'tld' ? 'suffix like “xyz”' : 'fragment like “doubleclick”' }} to start stopping queries.
        </p>
      </div>
    </section>
  </div>
</template>
