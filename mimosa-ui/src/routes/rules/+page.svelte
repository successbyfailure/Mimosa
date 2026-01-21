<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type Rule = {
    id: number;
    plugin: string;
    event_id: string;
    severity: string;
    description: string;
    min_last_hour: number;
    min_total: number;
    min_blocks_total: number;
    block_minutes?: number | null;
  };

  type RuleForm = {
    plugin: string;
    event_id: string;
    severity: string;
    description: string;
    min_last_hour: number;
    min_total: number;
    min_blocks_total: number;
    block_minutes: string;
  };

  let rules: Rule[] = [];
  type Offense = {
    id: number;
    source_ip: string;
    description: string;
    description_clean?: string;
    plugin?: string | null;
    severity?: string | null;
    created_at: string;
    context?: Record<string, unknown> | null;
  };

  type OffenseMatch = {
    offense: Offense;
    matches: number;
  };

  let offenses: Offense[] = [];
  let offenseMatches: OffenseMatch[] = [];
  let offensesLoading = false;
  let offensesError: string | null = null;
  let loading = false;
  let error: string | null = null;

  let form: RuleForm = {
    plugin: '*',
    event_id: '*',
    severity: '*',
    description: '*',
    min_last_hour: 0,
    min_total: 0,
    min_blocks_total: 0,
    block_minutes: ''
  };

  let editingId: number | null = null;
  let actionMessage: string | null = null;
  let actionError: string | null = null;
  let actionLoading = false;

  const pluginOptions = ['*', 'proxytrap', 'portdetector', 'mimosanpm', 'manual'];
  const severityOptions = ['*', 'bajo', 'medio', 'alto', 'critico'];

  const requestJson = async <T>(path: string, options?: RequestInit): Promise<T> => {
    const response = await fetch(path, {
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {})
      },
      credentials: 'include',
      ...options
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload?.detail || 'Error en la solicitud');
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json() as Promise<T>;
  };

  const ipHref = (ip: string) => `/ips/${encodeURIComponent(ip)}`;

  const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const matchesPattern = (pattern: string, value: string) => {
    const normalized = (pattern || '*').trim();
    if (!normalized || normalized === '*') {
      return true;
    }
    const regex = new RegExp(
      '^' + escapeRegex(normalized).replace(/\\\*/g, '.*').replace(/\\\?/g, '.') + '$',
      'i'
    );
    return regex.test(value || '');
  };

  const resolveEventId = (offense: Offense) => {
    const context = offense.context || {};
    const eventId =
      (context as Record<string, unknown>).event_id ||
      (context as Record<string, unknown>).alert_type ||
      '';
    if (eventId) {
      return String(eventId);
    }
    const description = offense.description || '';
    if (description.includes(':')) {
      const after = description.split(':')[1] || '';
      return after.trim().split(/\s+/)[0] || '';
    }
    return '';
  };

  const ruleMatches = (rule: Rule, offense: Offense) => {
    const plugin = (offense.plugin || (offense.context as Record<string, unknown>)?.plugin || '').toString();
    const severity = (offense.severity || '').toString();
    const eventId = resolveEventId(offense);
    const description = offense.description_clean || offense.description || '';
    return (
      matchesPattern(rule.plugin, plugin) &&
      matchesPattern(rule.severity, severity) &&
      matchesPattern(rule.event_id, eventId) &&
      matchesPattern(rule.description, description)
    );
  };

  const loadRules = async () => {
    loading = true;
    error = null;
    try {
      rules = await requestJson<Rule[]>('/api/rules');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const loadOffenses = async () => {
    offensesLoading = true;
    offensesError = null;
    try {
      offenses = await requestJson<Offense[]>('/api/offenses?limit=200');
    } catch (err) {
      offensesError = err instanceof Error ? err.message : 'No se pudieron cargar ofensas';
    } finally {
      offensesLoading = false;
    }
  };

  const resetForm = () => {
    form = {
      plugin: '*',
      event_id: '*',
      severity: '*',
      description: '*',
      min_last_hour: 0,
      min_total: 0,
      min_blocks_total: 0,
      block_minutes: ''
    };
    editingId = null;
  };

  const editRule = (rule: Rule) => {
    editingId = rule.id;
    form = {
      plugin: rule.plugin,
      event_id: rule.event_id,
      severity: rule.severity,
      description: rule.description,
      min_last_hour: rule.min_last_hour,
      min_total: rule.min_total,
      min_blocks_total: rule.min_blocks_total,
      block_minutes: rule.block_minutes ? String(rule.block_minutes) : ''
    };
    actionMessage = null;
    actionError = null;
  };

  const saveRule = async () => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const payload = {
        plugin: form.plugin.trim() || '*',
        event_id: form.event_id.trim() || '*',
        severity: form.severity.trim() || '*',
        description: form.description.trim() || '*',
        min_last_hour: Number(form.min_last_hour) || 0,
        min_total: Number(form.min_total) || 0,
        min_blocks_total: Number(form.min_blocks_total) || 0,
        block_minutes: form.block_minutes ? Number(form.block_minutes) : null
      };

      if (editingId) {
        await requestJson(`/api/rules/${editingId}`, {
          method: 'PUT',
          body: JSON.stringify(payload)
        });
        actionMessage = 'Regla actualizada';
      } else {
        await requestJson('/api/rules', {
          method: 'POST',
          body: JSON.stringify(payload)
        });
        actionMessage = 'Regla creada';
      }

      await loadRules();
      resetForm();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo guardar';
    } finally {
      actionLoading = false;
    }
  };

  const deleteRule = async (rule: Rule) => {
    if (!confirm(`Eliminar regla ${rule.id}?`)) {
      return;
    }
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      await requestJson(`/api/rules/${rule.id}`, { method: 'DELETE' });
      actionMessage = 'Regla eliminada';
      await loadRules();
      if (editingId === rule.id) {
        resetForm();
      }
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo eliminar';
    } finally {
      actionLoading = false;
    }
  };

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  $: offenseMatches = offenses.map((offense) => ({
    offense,
    matches: rules.filter((rule) => ruleMatches(rule, offense)).length
  }));

  onMount(() => {
    loadRules();
    loadOffenses();
  });
</script>

<section class="page-header">
  <div class="badge">Rules</div>
  <h1>Reglas de escalado</h1>
  <p>Configura los umbrales para bloqueos automaticos.</p>
</section>

{#if error}
  <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

<div class="section">
  <div class="surface" style="padding: 18px; overflow-x: auto;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <div class="badge">Reglas</div>
        <h3 style="margin-top: 12px;">Listado actual</h3>
      </div>
      <button class="ghost" on:click={loadRules}>Recargar</button>
    </div>
    <table class="table table-responsive" style="margin-top: 16px;">
      <thead>
        <tr>
          <th>ID</th>
          <th>Plugin</th>
          <th>Event</th>
          <th>Severidad</th>
          <th>Descripcion</th>
          <th>Umbrales</th>
          <th>Bloqueo</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#if loading}
          <tr>
            <td colspan="8">Cargando reglas...</td>
          </tr>
        {:else if rules.length === 0}
          <tr>
            <td colspan="8">Sin reglas.</td>
          </tr>
        {:else}
          {#each rules as rule}
            <tr>
              <td data-label="ID">{rule.id}</td>
              <td data-label="Plugin">{rule.plugin}</td>
              <td data-label="Event">{rule.event_id}</td>
              <td data-label="Severidad">{rule.severity}</td>
              <td data-label="Descripcion">{rule.description}</td>
              <td data-label="Umbrales">
                {rule.min_last_hour} / {rule.min_total} / {rule.min_blocks_total}
              </td>
              <td data-label="Bloqueo">{rule.block_minutes ?? '-'}</td>
              <td data-label="Accion">
                <div style="display: flex; gap: 8px;">
                  <button class="ghost" on:click={() => editRule(rule)}>Editar</button>
                  <button class="ghost" on:click={() => deleteRule(rule)}>Borrar</button>
                </div>
              </td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Nueva regla</div>
    <h3 style="margin-top: 12px;">{editingId ? 'Editar regla' : 'Crear regla'}</h3>
    <div style="display: grid; gap: 12px; margin-top: 12px;">
      <div class="split" style="gap: 12px;">
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Plugin</div>
          <select bind:value={form.plugin}>
            {#if form.plugin && !pluginOptions.includes(form.plugin)}
              <option value={form.plugin}>{form.plugin} (custom)</option>
            {/if}
            {#each pluginOptions as option}
              <option value={option}>{option}</option>
            {/each}
          </select>
        </label>
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Event ID</div>
          <input bind:value={form.event_id} placeholder="*" />
        </label>
      </div>
      <div class="split" style="gap: 12px;">
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Severidad</div>
          <select bind:value={form.severity}>
            {#if form.severity && !severityOptions.includes(form.severity)}
              <option value={form.severity}>{form.severity} (custom)</option>
            {/if}
            {#each severityOptions as option}
              <option value={option}>{option}</option>
            {/each}
          </select>
        </label>
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Descripcion</div>
          <input bind:value={form.description} placeholder="*" />
        </label>
      </div>
      <div class="split" style="gap: 12px;">
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Min. ultima hora</div>
          <input type="number" min="0" bind:value={form.min_last_hour} />
        </label>
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Min. total</div>
          <input type="number" min="0" bind:value={form.min_total} />
        </label>
      </div>
      <div class="split" style="gap: 12px;">
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Min. bloqueos</div>
          <input type="number" min="0" bind:value={form.min_blocks_total} />
        </label>
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
            Minutos de bloqueo
          </div>
          <input type="number" min="0" bind:value={form.block_minutes} />
        </label>
      </div>
    </div>
    {#if actionMessage}
      <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
        {actionMessage}
      </div>
    {/if}
    {#if actionError}
      <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
        {actionError}
      </div>
    {/if}
    <div style="margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap;">
      <button class="primary" disabled={actionLoading} on:click={saveRule}>
        {actionLoading ? 'Guardando...' : 'Guardar'}
      </button>
      {#if editingId}
        <button class="ghost" disabled={actionLoading} on:click={resetForm}>Cancelar</button>
      {/if}
    </div>
  </div>

  <div class="surface" style="padding: 18px; overflow-x: auto;">
    <div class="badge">Historial</div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h3 style="margin-top: 12px;">Ofensas recientes</h3>
      <button class="ghost" on:click={loadOffenses}>Recargar</button>
    </div>
    {#if offensesError}
      <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
        {offensesError}
      </div>
    {/if}
    <table class="table table-responsive" style="margin-top: 16px;">
      <thead>
        <tr>
          <th>Fecha</th>
          <th>IP</th>
          <th>Plugin</th>
          <th>Severidad</th>
          <th>Descripcion</th>
          <th>Matches</th>
        </tr>
      </thead>
      <tbody>
        {#if offensesLoading}
          <tr>
            <td colspan="6">Cargando ofensas...</td>
          </tr>
        {:else if offenseMatches.length === 0}
          <tr>
            <td colspan="6">Sin ofensas.</td>
          </tr>
        {:else}
          {#each offenseMatches as entry}
            <tr class={entry.matches > 0 ? 'offense-match' : 'offense-no-match'}>
              <td data-label="Fecha">
                {new Date(entry.offense.created_at).toLocaleString()}
              </td>
              <td data-label="IP">
                <a class="ip-link" href={ipHref(entry.offense.source_ip)}>
                  {entry.offense.source_ip}
                </a>
              </td>
              <td data-label="Plugin">{entry.offense.plugin || 'manual'}</td>
              <td data-label="Severidad">{entry.offense.severity || '-'}</td>
              <td data-label="Descripcion">
                {entry.offense.description_clean || entry.offense.description}
              </td>
              <td data-label="Matches">{entry.matches > 0 ? entry.matches : '-'}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</div>
