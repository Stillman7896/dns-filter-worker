<script setup>
const props = defineProps({
  modelValue: { type: [String, Number, Boolean], default: '' },
  options: { type: Array, required: true }, // [{ value, label }]
  label: { type: String, default: null },
});
const emit = defineEmits(['update:modelValue']);
</script>

<template>
  <div role="tablist" :aria-label="label || undefined" class="inline-flex flex-wrap gap-1 rounded-md border border-line bg-raised p-1">
    <button
      v-for="o in options"
      :key="o.value"
      type="button"
      role="tab"
      :aria-selected="props.modelValue === o.value"
      class="relative h-7 px-2.5 rounded text-[12.5px] font-medium transition-colors duration-150"
      :class="props.modelValue === o.value ? 'bg-beacon text-black' : 'text-muted hover:text-ink hover:bg-surface'"
      @click="emit('update:modelValue', o.value)"
    >
      {{ o.label }}
    </button>
  </div>
</template>