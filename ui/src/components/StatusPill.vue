<script setup>
import { computed } from 'vue';

const props = defineProps({ status: { type: String, required: true } });

const TOKENS = {
  none: { text: 'let through', cls: 'text-muted border-line' },
  allow: { text: 'allow rule', cls: 'text-pass border-pass/40' },
  deny: { text: 'deny rule', cls: 'text-block border-block/40' },
  blocklist: { text: 'blocklist', cls: 'text-block border-block/40' },
  tld: { text: 'TLD rule', cls: 'text-block border-block/40' },
  keyword: { text: 'keyword', cls: 'text-block border-block/40' },
  rebind: { text: 'rebinding', cls: 'text-block border-block/40' },
  idn: { text: 'punycode', cls: 'text-block border-block/40' },
};

const token = computed(() => TOKENS[props.status] || TOKENS.none);
</script>

<template>
  <span
    class="st inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11.5px]"
    :class="token.cls"
    :title="`status: ${status}`"
  >
    <span class="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
    {{ token.text }}
  </span>
</template>