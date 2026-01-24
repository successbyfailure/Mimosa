<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type BlockEntry = {
    id: number;
    ip: string;
    reason: string;
    reason_text?: string | null;
    reason_plugin?: string | null;
    reason_counts?: {
      offenses_total?: number | null;
      offenses_1h?: number | null;
      blocks_total?: number | null;
    };
    created_at: string;
    expires_at?: string | null;
    active: boolean;
    source?: string;
    sync_with_firewall?: boolean;
  };

  type BlockHistoryEntry = {
    ip: string;
    reason: string;
    reason_text?: string | null;
    reason_plugin?: string | null;
    reason_counts?: {
      offenses_total?: number | null;
      offenses_1h?: number | null;
      blocks_total?: number | null;
    };
    action: string;
    at: string;
    source?: string;
  };

  type FirewallConfig = {
    id: string;
    name: string;
    type: string;
    enabled?: boolean;
  };

  type BlockForm = {
    ip: string;
    reason: string;
    duration_minutes: number;
  };

  let blocks: BlockEntry[] = [];
  let history: BlockHistoryEntry[] = [];
  let firewalls: FirewallConfig[] = [];
  let selectedFirewallId = '';
  let includeExpired = false;
  let loading = false;
  let error: string | null = null;
  let historyLoading = false;

  let form: BlockForm = {
    ip: '',
    reason: '',
    duration_minutes: 60
  };

  let actionMessage: string | null = null;
  let actionError: string | null = null;
  let actionLoading = false;

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

  const loadBlocks = async () => {
    loading = true;
    error = null;
    try {
      blocks = await requestJson<BlockEntry[]>(
        `/api/blocks?include_expired=${includeExpired ? 'true' : 'false'}`
      );
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const loadHistory = async () => {
    historyLoading = true;
    try {
      history = await requestJson<BlockHistoryEntry[]>('/api/blocks/history?limit=20');
    } catch (err) {
      // optional
    } finally {
      historyLoading = false;
    }
  };

  const loadFirewalls = async () => {
    try {
      firewalls = await requestJson<FirewallConfig[]>('/api/firewalls');
      if (!selectedFirewallId) {
        const active = firewalls.find((fw) => fw.enabled !== false) || firewalls[0];
        if (active) {
          selectedFirewallId = active.id;
        }
      }
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudieron cargar firewalls';
    }
  };

  const activeFirewallId = () => {
    if (selectedFirewallId) {
      return selectedFirewallId;
    }
    if (firewalls.length === 1) {
      return firewalls[0].id;
    }
    return '';
  };

  const addBlock = async () => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const firewallId = activeFirewallId();
      if (!firewallId) {
        throw new Error('Selecciona un firewall');
      }
      const payload = {
        ip: form.ip.trim(),
        reason: form.reason.trim() || null,
        duration_minutes: Number(form.duration_minutes) || null,
        sync_with_firewall: false
      };
      if (!payload.ip) {
        throw new Error('IP obligatoria');
      }
      await requestJson(`/api/firewalls/${firewallId}/blocks`, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      actionMessage = 'Bloqueo creado';
      form.ip = '';
      form.reason = '';
      await loadBlocks();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo crear el bloqueo';
    } finally {
      actionLoading = false;
    }
  };

  const removeBlock = async (block: BlockEntry) => {
    if (!confirm(`Eliminar bloqueo para ${block.ip}?`)) {
      return;
    }
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const firewallId = activeFirewallId();
      if (!firewallId) {
        throw new Error('Selecciona un firewall');
      }
      await requestJson(`/api/firewalls/${firewallId}/blocks/${block.ip}`, {
        method: 'DELETE'
      });
      actionMessage = 'Bloqueo eliminado';
      await loadBlocks();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo eliminar';
    } finally {
      actionLoading = false;
    }
  };

  const formatDate = (value?: string | null) => {
    if (!value) {
      return '-';
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  };

  const handleFirewallChange = () => {
    // mantener seleccion sin sincronizar entradas al firewall
  };

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadBlocks();
    loadFirewalls();
    loadHistory();
  });
</script>

<section class="page-header">
  <div class="badge">Blocks</div>
  <h1>Bloqueos activos</h1>
  <p>Gestiona bloqueos temporales y el historico asociado.</p>
</section>

{#if error}
  <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

<div class="section">
  <div class="surface" style="padding: 18px;">
    <div class="toolbar">
      <label class="check-item">
        <input type="checkbox" bind:checked={includeExpired} />
        <span>Incluir expirados</span>
      </label>
      <select bind:value={selectedFirewallId} on:change={handleFirewallChange}>
        <option value="">Seleccionar firewall</option>
        {#each firewalls as firewall}
          <option value={firewall.id}>{firewall.name}</option>
        {/each}
      </select>
      <button class="ghost" on:click={loadBlocks}>Recargar</button>
    </div>

    <div style="margin-top: 16px; overflow-x: auto;">
      <table class="table table-responsive">
        <thead>
          <tr>
            <th>IP</th>
            <th>Estado</th>
            <th>Motivo</th>
            <th>Plugin</th>
            <th class="cell-right">Bloqueos</th>
            <th>Fuente</th>
            <th>Creado</th>
            <th>Expira</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#if loading}
            <tr>
              <td colspan="9">Cargando bloqueos...</td>
            </tr>
          {:else if blocks.length === 0}
            <tr>
              <td colspan="9">Sin bloqueos.</td>
            </tr>
          {:else}
            {#each blocks as block}
              <tr>
                <td data-label="IP">
                  <a class="ip-link" href={ipHref(block.ip)}>{block.ip}</a>
                </td>
                <td data-label="Estado">
                  <span
                    class="tag"
                    style="color: {block.active ? 'var(--success)' : 'var(--muted)'};"
                  >
                    {block.active ? 'Activo' : 'Inactivo'}
                  </span>
                </td>
                <td data-label="Motivo">{block.reason_text || block.reason || '-'}</td>
                <td data-label="Plugin">{block.reason_plugin || '-'}</td>
                <td class="cell-right" data-label="Bloqueos">
                  {block.reason_counts?.blocks_total ?? '-'}
                </td>
                <td data-label="Fuente">{block.source || '-'}</td>
                <td data-label="Creado">{formatDate(block.created_at)}</td>
                <td data-label="Expira">{formatDate(block.expires_at)}</td>
                <td data-label="Accion">
                  <button class="ghost" on:click={() => removeBlock(block)}>Eliminar</button>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Manual</div>
    <h3 style="margin-top: 12px;">Crear bloqueo</h3>
    <div style="display: grid; gap: 12px; margin-top: 12px;">
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Firewall</div>
        <select bind:value={selectedFirewallId} on:change={handleFirewallChange}>
          <option value="">Seleccionar</option>
          {#each firewalls as firewall}
            <option value={firewall.id}>{firewall.name}</option>
          {/each}
        </select>
      </label>
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">IP</div>
        <input bind:value={form.ip} placeholder="192.168.1.10" />
      </label>
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Motivo</div>
        <input bind:value={form.reason} placeholder="Motivo" />
      </label>
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
          Duracion (minutos)
        </div>
        <input type="number" min="1" step="1" bind:value={form.duration_minutes} />
      </label>
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
      <button class="primary" disabled={actionLoading} on:click={addBlock}>
        {actionLoading ? 'Guardando...' : 'Crear bloqueo'}
      </button>
    </div>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Historial</div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h3 style="margin-top: 12px;">Actividad reciente</h3>
      <button class="ghost" on:click={loadHistory}>Actualizar</button>
    </div>
    <div style="margin-top: 12px; overflow-x: auto;">
      <table class="table table-responsive">
        <thead>
          <tr>
            <th>Accion</th>
            <th>IP</th>
            <th>Motivo</th>
            <th>Fuente</th>
            <th>Momento</th>
          </tr>
        </thead>
        <tbody>
          {#if historyLoading}
            <tr><td colspan="5">Cargando historial...</td></tr>
          {:else if history.length === 0}
            <tr><td colspan="5">Sin historial.</td></tr>
          {:else}
            {#each history as entry}
              <tr>
                <td data-label="Accion">{entry.action}</td>
                <td data-label="IP">
                  <a class="ip-link" href={ipHref(entry.ip)}>{entry.ip}</a>
                </td>
                <td data-label="Motivo">{entry.reason_text || entry.reason || '-'}</td>
                <td data-label="Fuente">{entry.source || '-'}</td>
                <td data-label="Momento">{formatDate(entry.at)}</td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>
</div>
