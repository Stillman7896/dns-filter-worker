<script setup>
import { ref, computed, watch, nextTick, onBeforeUnmount } from 'vue';

// One dialog: backdrop click and Esc close it, Tab stays inside, and focus
// returns to whatever opened it. Content and an optional footer are slots.
const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, required: true },
});
const emit = defineEmits(['close']);

const panel = ref(null);
const titleId = computed(() => `dialog-${props.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')}`);
/** @type {Element|null} */
let restoreTo = null;

/** @param {KeyboardEvent} e */
function onKeydown(e) {
  if (e.key === 'Escape') {
    e.stopPropagation();
    emit('close');
    return;
  }
  if (e.key !== 'Tab' || !panel.value) return;
  const focusable = panel.value.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])',
  );
  if (!focusable.length) return;
  const first = /** @type {HTMLElement} */ (focusable[0]);
  const last = /** @type {HTMLElement} */ (focusable[focusable.length - 1]);
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

function release() {
  document.removeEventListener('keydown', onKeydown);
  document.body.style.overflow = '';
}

watch(() => props.open, async (open) => {
  if (open) {
    restoreTo = document.activeElement;
    document.addEventListener('keydown', onKeydown);
    document.body.style.overflow = 'hidden';
    await nextTick();
    panel.value?.focus();
  } else {
    release();
    if (restoreTo instanceof HTMLElement) restoreTo.focus();
    restoreTo = null;
  }
});

onBeforeUnmount(release);
</script>

<template>
  <Teleport to="body">
    <Transition name="sheet">
      <div v-if="open" class="fixed inset-0 z-50 flex items-end sm:items-center justify-center sm:p-6">
        <div class="absolute inset-0 bg-black/50" aria-hidden="true" @click="$emit('close')" />

        <div
          ref="panel"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="titleId"
          tabindex="-1"
          class="relative w-full sm:max-w-xl max-h-[88dvh] flex flex-col rounded-t-2xl sm:rounded-xl border border-line bg-surface shadow-[var(--shadow-card)] outline-none"
        >
          <div class="flex items-center gap-3 px-5 py-3.5 border-b border-line">
            <h2 :id="titleId" class="text-[15px] font-medium">{{ title }}</h2>
            <button
              type="button"
              class="-mr-1.5 ml-auto w-8 h-8 grid place-items-center rounded-md text-muted hover:text-ink hover:bg-raised transition-colors"
              aria-label="Close dialog"
              @click="$emit('close')"
            >
              <svg class="w-4 h-4" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
              </svg>
            </button>
          </div>

          <div class="px-5 py-4 overflow-y-auto"><slot /></div>

          <div v-if="$slots.footer" class="px-5 py-3 border-t border-line bg-raised/60">
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.sheet-enter-active,
.sheet-leave-active {
  transition: opacity 180ms ease;
}
.sheet-enter-active > div:last-child,
.sheet-leave-active > div:last-child {
  transition: transform 220ms cubic-bezier(0.2, 0.9, 0.3, 1), opacity 180ms ease;
}
.sheet-enter-from,
.sheet-leave-to {
  opacity: 0;
}
.sheet-enter-from > div:last-child,
.sheet-leave-to > div:last-child {
  transform: translateY(12px) scale(0.99);
}
</style>
