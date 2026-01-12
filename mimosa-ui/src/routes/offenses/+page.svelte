<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type Offense = {
    id: number;
    source_ip: string;
    description: string;
    description_clean?: string;
    plugin?: string | null;
    severity?: string | null;
    created_at: string;
    escalation_status?: string;
  };

  type OffenseForm = {
    source_ip: string;
    plugin: string;
    event_id: string;
    severity: string;
    description: string;
  };

  let offenses: Offense[] = [];
  let loading = false;
  let error: string | null = null;
  let limit = 100;
  let query = '';

  let form: OffenseForm = {
    source_ip: '',
    plugin: 'manual',
    event_id: 'manual',
    severity: 'medio',
    description: ''
  };

  let actionMessage: string | null = null;
  let actionError: string | null = null;
  let actionLoading = false;

  const loadOffenses = async () => {
    loading = true;
    error = null;
    try {
      const response = await fetch(`/api/offenses?limit=${limit}`, { credentials: 'include' });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload?.detail || 'No se pudieron cargar las ofensas');
      }
      offenses = (await response.json()) as Offense[];
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const createOffense = async () => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const payload = {
        source_ip: form.source_ip.trim(),
        plugin: form.plugin.trim() || 'manual',
        event_id: form.event_id.trim() || 'manual',
        severity: form.severity,
        description: form.description.trim()
      };
      if (!payload.source_ip || !payload.description) {
        throw new Error('IP y descripcion son obligatorias');
      }
      const response = await fetch('/api/offenses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload?.detail || 'No se pudo crear la ofensa');
      }
      actionMessage = 'Ofensa creada';
      form.description = '';
      await loadOffenses();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'Error al crear ofensa';
    } finally {
      actionLoading = false;
    }
  };

  const formatDate = (value: string) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  };

  const severityColor = (severity?: string | null) => {
    const normalized = (severity || '').toLowerCase();
    if (['alto', 'high', 'critico'].includes(normalized)) {
      return 'var(--danger)';
    }
    if (['medio', 'medium'].includes(normalized)) {
      return 'var(--warning)';
    }
    if (['bajo', 'low'].includes(normalized)) {
      return 'var(--success)';
    }
    return 'var(--muted)';
  };

  const statusLabel = (status?: string) => {
    if (status === 'direct') {
      return 'Directo';
    }
    if (status === 'warning') {
      return 'Alerta';
    }
    return 'Normal';
  };

  $: filtered = offenses.filter((offense) => {
    const needle = query.trim().toLowerCase();
    if (!needle) {
      return true;
    }
    return [
      offense.source_ip,
      offense.description_clean || offense.description,
      offense.plugin || '',
      offense.severity || ''
    ]
      .join(' ')
      .toLowerCase()
      .includes(needle);
  });

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadOffenses();
  });
</script>

<section class="page-header">
  <div class="badge">Offenses</div>
  <h1>Actividad detectada</h1>
  <p>Lista de ofensas recientes y creacion manual de eventos.</p>
</section>

{#if error}
  <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

<div class="section">
  <div class="surface" style="padding: 18px;">
    <div style="display: flex; flex-wrap: wrap; gap: 12px; align-items: center;">
      <div style="flex: 1; min-width: 200px;">
        <input placeholder="Buscar por IP, plugin, severidad" bind:value={query} />
      </div>
      <div style="width: 120px;">
        <input type="number" min="10" step="10" bind:value={limit} />
      </div>
      <button class="ghost" on:click={loadOffenses}>Recargar</button>
    </div>

    <div style="margin-top: 16px; overflow-x: auto;">
      <table class="table">
        <thead>
          <tr>
            <th>IP</th>
            <th>Severidad</th>
            <th>Estado</th>
            <th>Descripcion</th>
            <th>Plugin</th>
            <th>Fecha</th>
          </tr>
        </thead>
        <tbody>
          {#if loading}
            <tr>
              <td colspan="6">Cargando ofensas...</td>
            </tr>
          {:else if filtered.length === 0}
            <tr>
              <td colspan="6">Sin ofensas recientes.</td>
            </tr>
          {:else}
            {#each filtered as offense}
              <tr>
                <td>{offense.source_ip}</td>
                <td>
                  <span class="tag" style="color: {severityColor(offense.severity)};">
                    {offense.severity || 'n/a'}
                  </span>
                </td>
                <td>{statusLabel(offense.escalation_status)}</td>
                <td>{offense.description_clean || offense.description}</td>
                <td>{offense.plugin || 'manual'}</td>
                <td>{formatDate(offense.created_at)}</td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Manual</div>
    <h3 style="margin-top: 12px;">Crear ofensa</h3>
    <div style="display: grid; gap: 12px; margin-top: 12px;">
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">IP</div>
        <input bind:value={form.source_ip} placeholder="192.168.1.10" />
      </label>
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Descripcion</div>
        <input bind:value={form.description} placeholder="Motivo" />
      </label>
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Severidad</div>
        <select bind:value={form.severity}>
          <option value="bajo">Bajo</option>
          <option value="medio">Medio</option>
          <option value="alto">Alto</option>
        </select>
      </label>
      <div class="split" style="gap: 12px;">
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Plugin</div>
          <input bind:value={form.plugin} placeholder="manual" />
        </label>
        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Event ID</div>
          <input bind:value={form.event_id} placeholder="manual" />
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
    <div style="margin-top: 16px;">
      <button class="primary" disabled={actionLoading} on:click={createOffense}>
        {actionLoading ? 'Guardando...' : 'Crear ofensa'}
      </button>
    </div>
  </div>
</div>
