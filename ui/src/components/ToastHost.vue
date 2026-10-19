<script setup>
import { state, dismissToast } from '../store.js';

// Sticky alert stack: pending alerts track a backend operation, successes and
// failures fade out on their own ttl (a failure carries a close button too),
// so the stack never fills with alerts the reader already dealt with.
const TONE = {
  pending: { bar: 'bg-beacon', glyph: 'spinner', card: 'border-beacon/50' },
  success: { bar: 'bg-pass', glyph: 'check', card: 'border-pass/40' },
  error: { bar: 'bg-block', glyph: 'bang', card: 'border-block/50' },
};

function tone(kind) {
  return TONE[kind] || TONE.error;
}
</script>

<template>
  <div
    class="fixed z-50 inset-x-2 bottom-3 flex flex-col-reverse gap-2 pointer-events-none sm:inset-x-auto sm:left-auto sm:right-4 sm:w-[380px]"
    role="region"
    aria-label="Notifications"
    aria-live="polite"
  >
    <transition-group name="toast-list">
      <article
        v-for="t in state.toasts"
        :key="t.id"
        class="toast-enter pointer-events-auto relative overflow-hidden rounded-lg border shadow-[var(--shadow-card)] bg-surface backdrop-blur"
        :class="tone(t.kind).card"
      >
        <div class="flex items-start gap-3 px-3.5 py-3">
          <span class="mt-0.5 shrink-0" aria-hidden="true">
            <span v-if="t.kind === 'pending'" class="block w-4 h-4 rounded-full border-2 border-beacon border-t-transparent spin" />
            <svg v-else-if="t.kind === 'success'" class="w-4 h-4 text-pass" viewBox="0 0 16 16" fill="none">
              <path d="M3 8.5l3.2 3.2L13 5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
            </svg>
            <svg v-else class="w-4 h-4 text-block" viewBox="0 0 16 16" fill="none">
              <path d="M8 4v5" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
              <circle cx="8" cy="12" r="1.2" fill="currentColor" />
            </svg>
          </span>

          <div class="min-w-0 flex-1">
            <p class="toster font-medium text-ink break-words">{{ t.text }}</p>
            <p v-if="t.detail" class="toster mt-1 text-muted">{{ t.detail }}</p>
            <button
              v-if="t.action"
              type="button"
              class="mt-2.5 btn btn-sm"
              :class="t.kind === 'error' ? 'btn-ghost' : 'btn-solid'"
              @click="t.action.run(), dismissToast(t.id)"
            >
              {{ t.action.label }}
            </button>
          </div>

          <button
            v-if="t.kind === 'error'"
            type="button"
            class="shrink-0 -mr-1 -mt-1 w-7 h-7 rounded-md text-muted hover:text-ink hover:bg-raised grid place-items-center"
            aria-label="Dismiss notification"
            @click="dismissToast(t.id)"
          >
            <svg class="w-3.5 h-3.5" viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
            </svg>
          </button>
        </div>

        <div class="absolute inset-y-0 left-0 w-[3px]" :class="tone(t.kind).bar" aria-hidden="true" />
        <div
          v-if="t.ttl"
          class="absolute bottom-0 left-0 h-[2px] toast-progress"
          :class="tone(t.kind).bar"
          :style="{ '--toast-ttl': `${t.ttl}ms` }"
          aria-hidden="true"
        />
      </article>
    </transition-group>
  </div>
</template>

<style scoped>
.toast-list-enter-active { transition: all 220ms cubic-bezier(0.2, 0.9, 0.3, 1); }
.toast-list-leave-active { transition: all 180ms ease; }
.toast-list-enter-from { opacity: 0; transform: translateY(-10px) scale(0.98); }
.toast-list-leave-to { opacity: 0; transform: scale(0.97); }
.toast-list-move { transition: transform 220ms cubic-bezier(0.2, 0.9, 0.3, 1); }
</style>