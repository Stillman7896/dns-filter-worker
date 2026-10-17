<script setup>
import { computed } from 'vue';
import { state } from '../store.js';

// The button is wired to an operation key: while its operation runs it is
// disabled with a spinner, then flashes a check or a shake from the result.
const props = defineProps({
  busyKey: { type: String, default: null },
  variant: { type: String, default: 'ghost' },
  block: { type: Boolean, default: false },
  small: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
  type: { type: String, default: 'button' },
});

const busy = computed(() => Boolean(props.busyKey && state.ops[props.busyKey]));
const flash = computed(() => (props.busyKey ? state.flashes[props.busyKey] : null));

const cls = computed(() => [
  'btn',
  `btn-${props.variant}`,
  { 'w-full': props.block, 'btn-sm': props.small, nudge: flash.value === 'fail' },
]);
</script>

<template>
  <button :type="type" :class="cls" :disabled="disabled || busy" :aria-busy="busy || undefined">
    <span v-if="busy" class="block w-3 h-3 rounded-full border-2 border-current border-t-transparent spin" aria-hidden="true" />
    <svg
      v-else-if="flash === 'ok'"
      class="w-3.5 h-3.5"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
      :class="variant === 'solid' ? 'text-black' : 'text-pass'"
    >
      <path d="M3 8.5l3.2 3.2L13 5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    <span :class="busy && 'opacity-70'"><slot /></span>
  </button>
</template>