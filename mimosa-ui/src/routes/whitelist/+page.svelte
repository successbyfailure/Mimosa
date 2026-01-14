<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type WhitelistEntry = {
    id: number;
    cidr: string;
    note?: string | null;
    created_at: string;
  };

  type FirewallConfig = {
    id: string;
    name: string;
    type: string;
  };

  type BlacklistPayload = {
    alias: string;
    items: string[];
  };

  let entries: WhitelistEntry[] = [];
  let firewalls: FirewallConfig[] = [];
  let selectedFirewallId = '';
  let blacklistAlias = '';
  let blacklistEntries: string[] = [];
  let loading = false;
  let error: string | null = null;

  let cidr = '';
  let note = '';
  let actionMessage: string | null = null;
  let actionError: string | null = null;
  let actionLoading = false;

  let blacklistIp = '';
  let blacklistReason = '';
  let blacklistMessage: string | null = null;
  let blacklistError: string | null = null;

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
  const isIpTarget = (value: string) => !value.includes('/');

  const loadWhitelist = async () => {
    loading = true;
    error = null;
    try {
      entries = await requestJson<WhitelistEntry[]>('/api/whitelist');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const addEntry = async () => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const payload = {
        cidr: cidr.trim(),
        note: note.trim() || null
      };
      if (!payload.cidr) {
        throw new Error('CIDR obligatorio');
      }
      await requestJson('/api/whitelist', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      actionMessage = 'Whitelist actualizada';
      cidr = '';
      note = '';
      await loadWhitelist();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo agregar';
    } finally {
      actionLoading = false;
    }
  };

  const removeEntry = async (entry: WhitelistEntry) => {
    if (!confirm(`Eliminar ${entry.cidr}?`)) {
      return;
    }
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      await requestJson(`/api/whitelist/${entry.id}`, { method: 'DELETE' });
      actionMessage = 'Entrada eliminada';
      await loadWhitelist();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo eliminar';
    } finally {
      actionLoading = false;
    }
  };

  const loadFirewalls = async () => {
    try {
      firewalls = await requestJson<FirewallConfig[]>('/api/firewalls');
      if (!selectedFirewallId && firewalls.length === 1) {
        selectedFirewallId = firewalls[0].id;
      }
      loadBlacklist();
    } catch (err) {
      blacklistError = err instanceof Error ? err.message : 'No se pudieron cargar firewalls';
    }
  };

  const loadBlacklist = async () => {
    blacklistMessage = null;
    blacklistError = null;
    blacklistEntries = [];
    blacklistAlias = '';
    if (!selectedFirewallId) {
      return;
    }
    try {
      const payload = await requestJson<BlacklistPayload>(
        `/api/firewalls/${selectedFirewallId}/blacklist`
      );
      blacklistAlias = payload.alias;
      blacklistEntries = payload.items || [];
    } catch (err) {
      blacklistError = err instanceof Error ? err.message : 'No se pudo cargar blacklist';
    }
  };

  const addBlacklist = async () => {
    if (!selectedFirewallId) {
      blacklistError = 'Selecciona un firewall';
      return;
    }
    blacklistMessage = null;
    blacklistError = null;
    try {
      const payload = {
        ip: blacklistIp.trim(),
        reason: blacklistReason.trim() || null
      };
      if (!payload.ip) {
        throw new Error('IP obligatoria');
      }
      await requestJson(`/api/firewalls/${selectedFirewallId}/blacklist`, {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      blacklistMessage = 'Entrada añadida';
      blacklistIp = '';
      blacklistReason = '';
      await loadBlacklist();
    } catch (err) {
      blacklistError = err instanceof Error ? err.message : 'No se pudo añadir';
    }
  };

  const removeBlacklist = async (entry: string) => {
    if (!selectedFirewallId) {
      return;
    }
    if (!confirm(`Eliminar ${entry}?`)) {
      return;
    }
    blacklistMessage = null;
    blacklistError = null;
    try {
      await requestJson(`/api/firewalls/${selectedFirewallId}/blacklist/${entry}`, {
        method: 'DELETE'
      });
      blacklistMessage = 'Entrada eliminada';
      await loadBlacklist();
    } catch (err) {
      blacklistError = err instanceof Error ? err.message : 'No se pudo eliminar';
    }
  };

  const formatDate = (value: string) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  };

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadWhitelist();
    loadFirewalls();
  });
</script>

<section class="page-header">
  <div class="badge">Whitelist</div>
  <h1>Lista blanca</h1>
  <p>IPs o redes que nunca deben bloquearse.</p>
</section>

{#if error}
  <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

<div class="section">
  <div class="surface" style="padding: 18px;">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <div class="badge">Entradas</div>
        <h3 style="margin-top: 12px;">CIDRs permitidos</h3>
      </div>
      <button class="ghost" on:click={loadWhitelist}>Recargar</button>
    </div>

    <div style="margin-top: 16px; overflow-x: auto;">
      <table class="table table-responsive">
        <thead>
          <tr>
            <th>CIDR</th>
            <th>Nota</th>
            <th>Creado</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#if loading}
            <tr>
              <td colspan="4">Cargando whitelist...</td>
            </tr>
          {:else if entries.length === 0}
            <tr>
              <td colspan="4">Sin entradas.</td>
            </tr>
          {:else}
            {#each entries as entry}
              <tr>
                <td data-label="CIDR">
                  {#if isIpTarget(entry.cidr)}
                    <a class="ip-link" href={ipHref(entry.cidr)}>{entry.cidr}</a>
                  {:else}
                    {entry.cidr}
                  {/if}
                </td>
                <td data-label="Nota">{entry.note || '-'}</td>
                <td data-label="Creado">{formatDate(entry.created_at)}</td>
                <td data-label="Accion">
                  <button class="ghost" on:click={() => removeEntry(entry)}>Eliminar</button>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Nueva entrada</div>
    <h3 style="margin-top: 12px;">Agregar CIDR</h3>
    <div style="display: grid; gap: 12px; margin-top: 12px;">
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">CIDR</div>
        <input bind:value={cidr} placeholder="10.0.0.0/24" />
      </label>
      <label>
        <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Nota</div>
        <input bind:value={note} placeholder="Motivo" />
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
      <button class="primary" disabled={actionLoading} on:click={addEntry}>
        {actionLoading ? 'Guardando...' : 'Agregar'}
      </button>
    </div>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Blacklist</div>
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <h3 style="margin-top: 12px;">Alias {blacklistAlias || 'mimosa_blacklist'}</h3>
        <p style="margin: 0; color: var(--muted); font-size: 12px;">
          Bloqueos permanentes en el firewall seleccionado.
        </p>
      </div>
      <div style="display: flex; gap: 12px;">
        <select bind:value={selectedFirewallId} on:change={loadBlacklist}>
          <option value="">Seleccionar firewall</option>
          {#each firewalls as firewall}
            <option value={firewall.id}>{firewall.name}</option>
          {/each}
        </select>
        <button class="ghost" on:click={loadBlacklist}>Actualizar</button>
      </div>
    </div>

    <div class="split" style="margin-top: 16px; gap: 16px;">
      <div>
        <div style="display: grid; gap: 12px;">
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">IP</div>
            <input bind:value={blacklistIp} placeholder="203.0.113.33" />
          </label>
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Motivo</div>
            <input bind:value={blacklistReason} placeholder="Bloqueo permanente" />
          </label>
          <button class="ghost" on:click={addBlacklist}>Agregar a blacklist</button>
        </div>
        {#if blacklistMessage}
          <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
            {blacklistMessage}
          </div>
        {/if}
        {#if blacklistError}
          <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
            {blacklistError}
          </div>
        {/if}
      </div>
      <div style="overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th>Entrada</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#if !selectedFirewallId}
              <tr><td colspan="2">Selecciona un firewall.</td></tr>
            {:else if blacklistEntries.length === 0}
              <tr><td colspan="2">Sin entradas.</td></tr>
            {:else}
              {#each blacklistEntries as entry}
                <tr>
                  <td data-label="Entrada">
                    {#if isIpTarget(entry)}
                      <a class="ip-link" href={ipHref(entry)}>{entry}</a>
                    {:else}
                      {entry}
                    {/if}
                  </td>
                  <td data-label="Accion">
                    <button class="ghost" on:click={() => removeBlacklist(entry)}>Eliminar</button>
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
