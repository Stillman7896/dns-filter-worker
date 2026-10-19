<script setup>
import { ref, computed, onBeforeUnmount } from 'vue';

// A read-only value with one job: put it on the clipboard and say so.
// navigator.clipboard needs a secure context, so the execCommand path stays as
// the fallback for a dashboard opened over plain http on a LAN.
const props = defineProps({
  value: { type: String, required: true },
  label: { type: String, default: 'Value' },
});

const state = ref('idle'); // idle | copied | failed
/** @type {ReturnType<typeof setTimeout>|undefined} */
let reset;

const text = computed(() => (state.value === 'copied' ? 'Copied' : state.value === 'failed' ? 'Copy failed' : 'Copy'));

async function writeClipboard(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch { /* insecure context or denied permission */ }
  try {
    const field = document.createElement('textarea');
    field.value = value;
    field.setAttribute('readonly', '');
    field.style.position = 'fixed';
    field.style.opacity = '0';
    document.body.appendChild(field);
    field.select();
    const ok = document.execCommand('copy');
    field.remove();
    return ok;
  } catch {
    return false;
  }
}

async function copy() {
  state.value = (await writeClipboard(props.value)) ? 'copied' : 'failed';
  clearTimeout(reset);
  reset = setTimeout(() => { state.value = 'idle'; }, 1800);
}

onBeforeUnmount(() => clearTimeout(reset));
</script>

<template>
  <div class="flex items-stretch rounded-md border border-line bg-raised overflow-hidden">
    <code class="st flex-1 min-w-0 px-3 py-2.5 text-[12.5px] leading-relaxed break-all">{{ value }}</code>
    <button
      type="button"
      class="shrink-0 inline-flex items-center gap-1.5 px-3 border-l border-line text-[12.5px] font-medium transition-colors hover:bg-surface"
      :class="state === 'copied' ? 'text-pass' : state === 'failed' ? 'text-block' : 'text-muted hover:text-ink'"
      :aria-label="`Copy ${label}`"
      @click="copy"
    >
      <svg v-if="state === 'copied'" class="w-3.5 h-3.5" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M3 8.5l3.2 3.2L13 5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
      <svg v-else class="w-3.5 h-3.5" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <rect x="5.5" y="5.5" width="8" height="8" rx="1.5" stroke="currentColor" stroke-width="1.4" />
        <path d="M10.5 5V3.5A1.5 1.5 0 0 0 9 2H3.5A1.5 1.5 0 0 0 2 3.5V9a1.5 1.5 0 0 0 1.5 1.5H5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
      </svg>
      <span aria-live="polite">{{ text }}</span>
    </button>
  </div>
</template>
