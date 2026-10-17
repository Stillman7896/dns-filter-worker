<script setup>
import { ref, onBeforeUnmount } from 'vue';
import AppButton from './AppButton.vue';

// Destructive action that arms itself: the first press states the cost, the
// second press executes. Auto-disarms so nothing stays armed by accident.
const props = defineProps({
  label: { type: String, required: true },
  armedLabel: { type: String, required: true },
  busyKey: { type: String, default: null },
  small: { type: Boolean, default: false },
});
const emit = defineEmits(['confirm']);

const armed = ref(false);
let timer = null;

function disarm() {
  armed.value = false;
  clearTimeout(timer);
}

function onClick() {
  if (armed.value) {
    disarm();
    emit('confirm');
  } else {
    armed.value = true;
    timer = setTimeout(disarm, 5000);
  }
}

onBeforeUnmount(() => clearTimeout(timer));
</script>

<template>
  <AppButton
    variant="danger"
    :busy-key="busyKey"
    :small="small"
    :class="armed && 'bg-block text-white border-block'"
    @click="onClick"
  >
    {{ armed ? props.armedLabel : props.label }}
  </AppButton>
</template>