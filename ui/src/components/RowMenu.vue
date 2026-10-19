<script setup>
import { ref, computed, onBeforeUnmount, nextTick } from 'vue';
import { state } from '../store.js';

// Row-level quick actions behind one button, so a table row stays one line
// tall on narrow screens. The menu is teleported to the body: a table cell
// scrolls horizontally, and a popover left inside it would be clipped.
// The destructive pick arms first (same idea as ConfirmButton) and disarms
// itself if it is left alone.
const props = defineProps({
  label: { type: String, required: true },
  keys: { type: Array, default: () => [] },
});
const emit = defineEmits(['allow', 'block', 'remove']);

const open = ref(false);
const armed = ref(false);
const pos = ref({ top: 0, right: 0 });
const root = ref(null);
const menu = ref(null);
let armTimer = null;

const busy = computed(() => props.keys.some((k) => state.ops[k]));

function listen(on) {
  const method = on ? 'addEventListener' : 'removeEventListener';
  document[method]('pointerdown', onOutside, true);
  document[method]('keydown', onKey);
  window[method]('scroll', close, { capture: true, passive: true });
}

function onOutside(e) {
  if (root.value?.contains(e.target) || menu.value?.contains(e.target)) return;
  close();
}

function onKey(e) {
  if (e.key === 'Escape') close();
}

function close() {
  if (!open.value) return;
  open.value = false;
  armed.value = false;
  clearTimeout(armTimer);
  listen(false);
}

async function toggle() {
  if (open.value) return close();
  open.value = true;
  armed.value = false;
  const r = root.value.getBoundingClientRect();
  pos.value = { top: Math.round(r.bottom + 4), right: Math.round(window.innerWidth - r.right) };
  listen(true);
  await nextTick();
  menu.value?.querySelector('button')?.focus();
}

function pick(action) {
  if (action === 'remove' && !armed.value) {
    armed.value = true;
    clearTimeout(armTimer);
    armTimer = setTimeout(() => { armed.value = false; }, 5000);
    return;
  }
  close();
  emit(action);
}

onBeforeUnmount(close);
</script>

<template>
  <div ref="root" class="relative inline-block text-left">
    <button
      type="button"
      class="btn btn-ghost btn-sm px-1.5"
      :aria-label="label"
      aria-haspopup="menu"
      :aria-expanded="open"
      :disabled="busy"
      @click="toggle"
    >
      <span v-if="busy" class="block w-3 h-3 rounded-full border-2 border-current border-t-transparent spin" aria-hidden="true" />
      <svg v-else class="w-4 h-4" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <circle cx="3" cy="8" r="1.4" />
        <circle cx="8" cy="8" r="1.4" />
        <circle cx="13" cy="8" r="1.4" />
      </svg>
    </button>

    <Teleport to="body">
      <ul
        v-if="open"
        ref="menu"
        role="menu"
        class="fixed z-50 w-40 rounded-md border border-line bg-surface p-1 shadow-[var(--shadow-card)]"
        :style="{ top: pos.top + 'px', right: pos.right + 'px' }"
      >
        <li role="none">
          <button role="menuitem" type="button" class="menu-item" @click="pick('allow')">Allow</button>
        </li>
        <li role="none">
          <button role="menuitem" type="button" class="menu-item" @click="pick('block')">Block</button>
        </li>
        <li role="none">
          <button role="menuitem" type="button" class="menu-item text-block" @click="pick('remove')">
            {{ armed ? 'Delete row?' : 'Remove' }}
          </button>
        </li>
      </ul>
    </Teleport>
  </div>
</template>
