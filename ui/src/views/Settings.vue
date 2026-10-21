<script setup>
import { ref, computed, watch } from 'vue';
import { state, runOp, loadRoutes, setRoute } from '../store.js';
import { api, ApiError } from '../api.js';
import AppButton from '../components/AppButton.vue';
import ConfirmButton from '../components/ConfirmButton.vue';
import ToggleSwitch from '../components/ToggleSwitch.vue';
import { normalizeDomain, normalizeRouteValue, isHttpsUrl, isRelayTemplate } from '../validate.js';

const TOGGLES = [
  {
    key: 'rebindProtection',
    label: 'Answer rebinding guard',
    effect: 'Refuse answers that point at private or local addresses, and any query for an internal hostname.',
  },
  {
    key: 'idnBlock',
    label: 'Punycode (IDN) hosts',
    effect: 'Refuse every internationalised hostname, so no look-alike spelling can slip through.',
  },
  {
    key: 'tldBlock',
    label: 'Blocked TLD list',
    effect: 'Refuse the suffixes listed on the Filter lists page.',
    route: 'lists',
  },
  {
    key: 'keywordBlock',
    label: 'Blocked keywords',
    effect: 'Refuse any query whose labels contain a keyword from the Filter lists page.',
    route: 'lists',
  },
  {
    key: 'regexBlock',
    label: 'Regex blocking',
    effect: 'Refuse any query name that matches a pattern from the Filter lists page.',
    route: 'lists',
  },
  {
    key: 'logPassed',
    label: 'Record allowed queries',
    effect: 'Keep a log row for answers that went through. Switch off to log only what was stopped.',
  },
];

const retention = ref(state.settings ? String(state.settings.logRetentionDays) : '30');
const retentionError = ref('');

const ready = computed(() => Boolean(state.settings));
const retentionValid = computed(() => Number.isInteger(Number(retention.value)) && Number(retention.value) >= 0 && Number(retention.value) <= 3650);

async function toggle(t, value) {
  const previous = state.settings[t.key];
  state.settings[t.key] = value; // optimistic; reverted if the worker refuses
  try {
    await runOp(`set.${t.key}`, {
      verb: 'Save settings',
      ok: `${t.label} ${value ? 'on' : 'off'}`,
      fn: () => api.saveSettings({ [t.key]: value }),
    });
  } catch {
    state.settings[t.key] = previous;
  }
}

async function saveRetention() {
  retentionError.value = '';
  if (!retentionValid.value) {
    retentionError.value = 'Enter a whole number of days between 0 and 3650.';
    return;
  }
  try {
    await runOp('set.retention', {
      verb: 'Save settings',
      ok: `Log kept ${Number(retention.value) === 0 ? 'forever' : `for ${retention.value} days`}`,
      fn: async () => {
        const r = await api.saveSettings({ logRetentionDays: Number(retention.value) });
        retention.value = String(r.settings.logRetentionDays);
        return r;
      },
    });
  } catch {
    retention.value = String(state.settings.logRetentionDays);
  }
}

// ---- upstream resolver -------------------------------------------------------

const provider = ref(state.settings?.upstreamPreset || '');
const customUrl = ref(state.settings?.upstreamUrl || '');
const relay = ref(state.settings?.upstreamRelay || '');
const probe = ref(null);

const presets = computed(() => state.upstreamPresets || []);
const groups = computed(() => {
  /** @type {string[]} */
  const order = [];
  /** @type {Map<string, any[]>} */
  const byGroup = new Map();
  for (const p of presets.value) {
    if (!byGroup.has(p.group)) {
      byGroup.set(p.group, []);
      order.push(p.group);
    }
    /** @type {any[]} */ (byGroup.get(p.group)).push(p);
  }
  return order.map((label) => ({ label, items: byGroup.get(label) || [] }));
});

const chosen = computed(() => presets.value.find((p) => p.id === provider.value) || null);
const effective = computed(() => state.upstream);
const sourceNote = computed(() => {
  const source = effective.value?.source;
  if (source === 'deploy') return 'Currently pinned by the UPSTREAM_URL deployment variable. Saving a provider here takes over.';
  if (source === 'default') return 'No provider saved yet — this is the built-in default.';
  return 'Saved in this dashboard.';
});

const isCustom = computed(() => provider.value === 'custom');
const isOdoh = computed(() => chosen.value?.kind === 'odoh');
const urlProblem = computed(() => (isCustom.value && customUrl.value.trim() && !isHttpsUrl(customUrl.value)
  ? 'Needs an https:// URL, like https://doh.example.com/dns-query.'
  : ''));
const relayProblem = computed(() => (isOdoh.value && relay.value.trim() && !isRelayTemplate(relay.value)
  ? 'Needs an https:// template containing {?targethost,targetpath}.'
  : ''));

const saved = computed(() => ({
  preset: state.settings?.upstreamPreset || '',
  url: state.settings?.upstreamUrl || '',
  relay: state.settings?.upstreamRelay || '',
}));
const dirty = computed(() => provider.value !== saved.value.preset
  || (isCustom.value && customUrl.value.trim() !== saved.value.url)
  || (isOdoh.value && relay.value.trim() !== saved.value.relay));
const canSave = computed(() => {
  if (!dirty.value) return false;
  if (isCustom.value) return isHttpsUrl(customUrl.value);
  if (isOdoh.value) return isRelayTemplate(relay.value);
  return true;
});
// Testing needs a complete target, whether or not it has been saved yet.
const canProbe = computed(() => {
  if (isCustom.value) return isHttpsUrl(customUrl.value);
  if (isOdoh.value) return isRelayTemplate(relay.value);
  return true;
});

/** Apply a settings response to the shared state. */
function applyConfig(r) {
  state.settings = r.settings;
  if (r.upstream) state.upstream = r.upstream;
}

async function saveProvider() {
  const before = { ...saved.value };
  if (!canSave.value) return;
  const patch = /** @type {Record<string, string>} */ ({ upstreamPreset: provider.value });
  if (isCustom.value) patch.upstreamUrl = customUrl.value.trim();
  if (isOdoh.value) patch.upstreamRelay = relay.value.trim();

  try {
    await runOp('settings.upstream', {
      verb: 'Save provider',
      ok: (r) => `Upstream: ${r.upstream.label}`,
      undo: async () => applyConfig(await api.saveSettings({
        upstreamPreset: before.preset,
        upstreamUrl: before.url,
        upstreamRelay: before.relay,
      })),
      fn: async () => {
        const r = await api.saveSettings(patch);
        applyConfig(r);
        probe.value = null;
        return r;
      },
    });
  } catch {
    provider.value = before.preset;
    probe.value = null;
  }
}

/** Presets save on pick; the two configurable ones wait for their field. */
function onPickProvider() {
  probe.value = null;
  if (isCustom.value || isOdoh.value) return;
  saveProvider();
}

async function testConnection() {
  probe.value = null;
  const candidate = provider.value
    ? { preset: provider.value, url: customUrl.value.trim(), relay: relay.value.trim() }
    : { url: effective.value?.url, kind: effective.value?.kind, relay: effective.value?.relay };

  await runOp('settings.probe', {
    verb: 'Test upstream',
    ok: (r) => `${r.kind === 'odoh' ? 'Relay and resolver' : 'Resolver'} answered in ${r.ms} ms`,
    fn: async () => {
      const r = await api.testUpstream(candidate);
      probe.value = r;
      // A probe that reached nothing is still an answer worth showing in the
      // panel, but the alert should say it failed.
      if (!r.ok) throw new ApiError(r.error || 'no answer', 0, 'probe');
      return r;
    },
  }).catch(() => {});
}

// ---- domain response routing --------------------------------------------------

const routeDomain = ref('');
const routeValue = ref('');
const routeTtl = ref('300');

const routeAnswer = computed(() => normalizeRouteValue(routeValue.value));
const routeDomainOk = computed(() => Boolean(normalizeDomain(routeDomain.value.trim())));
const routeTtlOk = computed(() => {
  const n = Number(routeTtl.value === '' ? 300 : routeTtl.value);
  return Number.isInteger(n) && n >= 0 && n <= 86_400;
});
const routeReady = computed(() => routeDomainOk.value && Boolean(routeAnswer.value) && routeTtlOk.value);
const routeHint = computed(() => {
  const raw = routeValue.value.trim();
  if (raw && !routeAnswer.value) return 'Needs an IPv4 or IPv6 address, or a hostname to point at.';
  if (!raw) return 'A route answers this name and every subdomain — before any other filter, including allow and deny rules.';
  const answer = routeAnswer.value;
  if (answer.type === 'cname') return `Saves as a CNAME to ${answer.value}.`;
  return `Saves as an ${answer.type.toUpperCase()} record for ${answer.value}.`;
});
const answerLabel = (r) => `${r.type.toUpperCase()} · ${r.value}`;

watch(provider, () => {
  // Keep the fields showing what is actually stored when switching back.
  customUrl.value = state.settings?.upstreamUrl || customUrl.value;
  relay.value = state.settings?.upstreamRelay || relay.value;
});

async function addRoute() {
  if (!routeReady.value) return;
  const payload = {
    domain: routeDomain.value.trim(),
    value: routeValue.value.trim(),
    ttl: Number(routeTtl.value === '' ? 300 : routeTtl.value),
  };
  try {
    await runOp('routes.add', {
      verb: 'Add route',
      ok: (r) => `${r.route.domain} → ${r.route.value}`,
      undo: async (r) => {
        await api.deleteRoute(r.route.domain);
        await loadRoutes();
      },
      fn: async () => {
        const r = await api.addRoute(payload);
        await loadRoutes();
        return r;
      },
    });
    routeDomain.value = '';
    routeValue.value = '';
    routeTtl.value = '300';
  } catch { /* the alert stack carries the reason; the form keeps its values */ }
}

async function removeRoute(route) {
  await runOp(`routes.del:${route.domain}`, {
    verb: 'Remove route',
    ok: `${route.domain} removed`,
    undo: async () => {
      await api.addRoute({ domain: route.domain, value: route.value, ttl: route.ttl });
      await loadRoutes();
    },
    fn: async () => {
      await api.deleteRoute(route.domain);
      await loadRoutes();
      return route;
    },
  }).catch(() => {});
}
</script>

<template>
  <div class="space-y-6">
    <div>
      <h1 class="text-[21px] font-semibold tracking-tight">Settings</h1>
      <p class="hint mt-1">Each change is written to KV as you make it — there is nothing else to save.</p>
    </div>

    <div v-if="!ready" class="panel p-6 text-center text-muted text-[13px]">
      <span class="block w-5 h-5 mx-auto rounded-full border-2 border-beacon border-t-transparent spin" aria-hidden="true" />
      <p class="mt-3">Reading current settings…</p>
    </div>

    <template v-else>
      <!-- Upstream resolver -->
      <section class="panel px-5 py-4">
        <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h2 class="text-[15px] font-medium">Upstream resolver</h2>
          <span class="text-[12.5px] text-muted">where allowed queries are forwarded</span>
        </div>

        <div class="mt-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
          <label class="flex flex-col gap-1.5 min-w-0">
            <span class="label">Provider</span>
            <select
              v-model="provider"
              class="field w-full"
              aria-describedby="provider-note"
              @change="onPickProvider"
            >
              <option value="">Default — {{ effective?.label }}</option>
              <optgroup v-for="g in groups" :key="g.label" :label="g.label">
                <option v-for="p in g.items" :key="p.id" :value="p.id">{{ p.label }}</option>
              </optgroup>
            </select>
          </label>

          <AppButton busy-key="settings.probe" :disabled="!canProbe" @click="testConnection">
            Test connection
          </AppButton>
        </div>

        <p id="provider-note" class="hint mt-2.5" aria-live="polite">
          {{ chosen?.note || effective?.note || 'Any RFC 8484 endpoint works.' }}
        </p>

        <div v-if="isCustom" class="mt-3 flex flex-col gap-1.5">
          <label class="label" for="custom-url">DoH URL</label>
          <div class="flex flex-wrap gap-2.5">
            <input
              id="custom-url"
              v-model="customUrl"
              @input="customUrl = $event.target.value"
              type="url"
              class="field flex-1 min-w-[220px] st"
              placeholder="https://doh.example.com/dns-query"
              autocapitalize="none"
              spellcheck="false"
              :aria-invalid="Boolean(urlProblem)"
            />
            <AppButton variant="solid" busy-key="settings.upstream" :disabled="!canSave" @click="saveProvider">
              Save provider
            </AppButton>
          </div>
          <p class="hint" :class="urlProblem && 'text-block'" aria-live="polite">
            {{ urlProblem || 'The worker must be able to reach this URL over https.' }}
          </p>
        </div>

        <div v-if="isOdoh" class="mt-3 flex flex-col gap-1.5">
          <label class="label" for="odoh-relay">Relay template</label>
          <div class="flex flex-wrap gap-2.5">
            <input
              id="odoh-relay"
              v-model="relay"
              @input="relay = $event.target.value"
              type="url"
              class="field flex-1 min-w-[220px] st"
              placeholder="https://relay.example/proxy{?targethost,targetpath}"
              autocapitalize="none"
              spellcheck="false"
              :aria-invalid="Boolean(relayProblem)"
            />
            <AppButton variant="solid" busy-key="settings.upstream" :disabled="!canSave" @click="saveProvider">
              Save provider
            </AppButton>
          </div>
          <p class="hint" :class="relayProblem && 'text-block'" aria-live="polite">
            {{ relayProblem || 'Queries are encrypted for the resolver and posted through this relay, so neither end sees both the name and your network.' }}
          </p>
        </div>

        <div class="mt-4 rounded-md border border-line bg-raised px-3.5 py-3">
          <div class="flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span class="text-[12.5px] text-muted">In use</span>
            <span class="st text-[12.5px] break-all">{{ effective?.url }}</span>
            <span
              v-if="effective?.kind === 'odoh'"
              class="st text-[11.5px] rounded border border-beacon/40 text-beacon px-1.5 py-0.5"
            >ODoH</span>
            <span v-if="dirty" class="text-[12px] text-beacon">· unsaved change above</span>
          </div>
          <p v-if="effective?.kind === 'odoh' && effective?.relay" class="st text-[12px] text-muted mt-1.5 break-all">
            relay {{ effective.relay }}
          </p>
          <p class="hint mt-1.5">{{ sourceNote }}</p>
        </div>

        <!-- Probe result -->
        <div
          v-if="probe"
          class="mt-3 rounded-md border px-3.5 py-3 rise-in"
          :class="probe.ok ? 'border-pass/40 bg-pass/5' : 'border-block/40 bg-block/5'"
          aria-live="polite"
        >
          <p class="text-[13px] font-medium" :class="probe.ok ? 'text-pass' : 'text-block'">
            {{ probe.ok ? 'Answered' : 'No answer' }} · {{ probe.ms }} ms
          </p>
          <p v-if="probe.ok" class="st text-[12.5px] text-muted mt-1 break-all">
            {{ probe.answers }} {{ probe.answers === 1 ? 'record' : 'records' }}
            <template v-if="probe.sample"> · {{ probe.sample }}</template>
          </p>
          <p v-else class="hint mt-1">{{ probe.error }}</p>
          <p class="st text-[11.5px] text-muted mt-1.5 break-all">{{ probe.kind === 'odoh' ? `via ${probe.url}` : probe.url }}</p>
        </div>
      </section>

      <!-- Domain response routing -->
      <section class="panel overflow-hidden">
        <div class="px-5 py-4 border-b border-line">
          <div class="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h2 class="text-[15px] font-medium">Domain response routing</h2>
            <span class="text-[12.5px] text-muted">{{ state.routes.length }} {{ state.routes.length === 1 ? 'route' : 'routes' }}</span>
          </div>
          <p class="hint mt-1">
            Answer a name — and every subdomain — with a fixed record instead of asking upstream.
            Private addresses and local names are welcome here; the route is checked before every other filter.
          </p>
        </div>

        <div class="px-5 py-4">
          <form class="grid gap-2.5 sm:grid-cols-[minmax(0,1.4fr)_minmax(0,1.2fr)_auto_auto] sm:items-end" @submit.prevent="addRoute">
            <label class="flex flex-col gap-1.5 min-w-0">
              <span class="label">Domain</span>
              <input
                v-model="routeDomain"
                @input="routeDomain = $event.target.value"
                type="text"
                class="field st"
                placeholder="nas.home.lan"
                autocapitalize="none"
                spellcheck="false"
                :aria-invalid="routeDomain.trim() && !routeDomainOk"
              />
            </label>
            <label class="flex flex-col gap-1.5 min-w-0">
              <span class="label">Answer</span>
              <input
                v-model="routeValue"
                @input="routeValue = $event.target.value"
                type="text"
                class="field st"
                placeholder="192.168.1.20 or hostname"
                autocapitalize="none"
                spellcheck="false"
                :aria-invalid="routeValue.trim() && !routeAnswer"
              />
            </label>
            <label class="flex flex-col gap-1.5">
              <span class="label">TTL</span>
              <input
                v-model="routeTtl"
                type="number"
                min="0"
                max="86400"
                step="1"
                class="field w-24 st"
                aria-label="Route TTL in seconds"
                :aria-invalid="!routeTtlOk"
              />
            </label>
            <AppButton variant="solid" type="submit" busy-key="routes.add" :disabled="!routeReady">
              Add route
            </AppButton>
          </form>

          <p class="hint mt-2.5" :class="(routeValue.trim() && !routeAnswer) || !routeTtlOk ? 'text-block' : ''" aria-live="polite">
            {{ !routeTtlOk ? 'TTL must be a whole number of seconds between 0 and 86400.' : routeHint }}
          </p>
        </div>

        <div v-if="state.routes.length" class="overflow-x-auto border-t border-line">
          <table class="w-full min-w-[480px] border-collapse text-left">
            <caption class="sr-only">Domain response routes</caption>
            <thead class="text-[12.5px] text-muted border-b border-line">
              <tr>
                <th scope="col" class="px-5 py-2 font-medium">Domain</th>
                <th scope="col" class="px-3 py-2 font-medium">Answer</th>
                <th scope="col" class="px-3 py-2 font-medium text-right whitespace-nowrap">TTL</th>
                <th scope="col" class="px-5 py-2 font-medium text-right"><span class="sr-only">Action</span></th>
              </tr>
            </thead>
            <tbody class="divide-y divide-line/70">
              <tr v-for="r in state.routes" :key="r.domain" class="hover:bg-raised/60 transition-colors">
                <td class="px-5 py-3 w-full min-w-0">
                  <span class="st text-[13.5px] truncate block" :title="r.domain">{{ r.domain }}</span>
                </td>
                <td class="px-3 py-3 whitespace-nowrap">
                  <span class="st text-[12.5px] rounded border border-line bg-raised px-2 py-0.5" :title="r.value">
                    {{ answerLabel(r) }}
                  </span>
                </td>
                <td class="px-3 py-3 text-right st text-[12.5px] text-muted whitespace-nowrap">{{ r.ttl }} s</td>
                <td class="px-5 py-3 text-right whitespace-nowrap">
                  <ConfirmButton
                    small
                    label="Remove"
                    armed-label="Confirm?"
                    :busy-key="`routes.del:${r.domain}`"
                    @confirm="removeRoute(r)"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <p v-else class="px-5 py-8 text-center hint border-t border-line">
          No routes yet — add one to serve a local name, pin a hostname to an IP, or alias a domain.
        </p>
      </section>

      <!-- Filters -->
      <section class="panel px-5 py-4">
        <h2 class="text-[15px] font-medium">Filters</h2>
        <div class="mt-1 divide-y divide-line/70" role="group" aria-label="Filter settings">
          <template v-for="t in TOGGLES" :key="t.key">
            <div class="flex items-start justify-between gap-4 py-3.5">
              <ToggleSwitch
                class="flex-1 !py-0"
                :model-value="state.settings[t.key]"
                :label="t.label"
                :effect="t.effect"
                :busy-key="`set.${t.key}`"
                @update:model-value="toggle(t, $event)"
              />
              <button
                v-if="t.route"
                type="button"
                class="shrink-0 mt-1 text-[13px] text-muted hover:text-ink underline underline-offset-2"
                @click="setRoute(t.route)"
              >
                Open list
              </button>
            </div>
          </template>
        </div>
      </section>

      <!-- Query log -->
      <section class="panel px-5 py-4">
        <h2 class="text-[15px] font-medium">Query log</h2>
        <p class="hint mt-1">Older rows are deleted by a scheduled job.</p>

        <div class="mt-4 flex flex-wrap items-end gap-3">
          <label class="flex flex-col gap-1.5">
            <span class="label">Keep rows for</span>
            <span class="flex items-center gap-2">
              <input
                v-model="retention"
                type="number"
                min="0"
                max="3650"
                step="1"
                class="field w-28 st"
                :aria-invalid="Boolean(retentionError)"
                aria-describedby="ret-hint"
                @input="retentionError = ''"
                @keyup.enter="saveRetention"
              />
              <span class="text-[13px] text-muted">days</span>
            </span>
          </label>

          <AppButton variant="solid" busy-key="set.retention" :disabled="!retentionValid" @click="saveRetention">
            Save retention
          </AppButton>

          <span id="ret-hint" class="hint" :class="retentionError ? 'text-block' : ''">
            {{ retentionError || (Number(retention) === 0 ? '0 keeps rows forever.' : `Drops on day ${Number(retention) + 1}.`) }}
          </span>
        </div>
      </section>
    </template>
  </div>
</template>

<style scoped>
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
}
</style>
