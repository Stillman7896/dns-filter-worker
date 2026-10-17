<script setup>
import { computed } from 'vue';
import { state } from '../store.js';

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  label: { type: String, required: true },
  effect: { type: String, default: '' },
  busyKey: { type: String, default: null },
});
const emit = defineEmits(['update:modelValue']);

const busy = computed(() => Boolean(props.busyKey && state.ops[props.busyKey]));
</script>

<template>
  <div class="flex items-start justify-between gap-4">
    <div class="min-w-0">
      <span class="label inline-flex items-center gap-2">
        {{ label }}
        <span v-if="busy" class="block w-3 h-3 rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
      </span>
      <p class="hint mt-0.5">{{ effect }}</p>
    </div>
    <button
      type="button"
      role="switch"
      :aria-checked="modelValue"
      :aria-label="label"
      class="shrink-0 mt-0.5 w-10 h-6 rounded-full border transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-beacon"
      :class="modelValue ? 'bg-beacon border-beacon' : 'bg-raised border-line'"
      :disabled="busy"
      @click="emit('update:modelValue', !modelValue)"
    >
      <span
        class="block w-4 h-4 mt-0.5 ml-0.5 rounded-full bg-white shadow transition-transform duration-150"
        :class="modelValue ? 'translate-x-4' : 'translate-x-0'"
        aria-hidden="true"
      />
    </button>
  </div>
</template>