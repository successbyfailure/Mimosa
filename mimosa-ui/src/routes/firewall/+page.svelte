<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type FirewallConfig = {
    id: string;
    name: string;
    type: string;
    enabled?: boolean;
  };

  type FirewallAliases = {
    aliases: {
      temporal: string;
      blacklist: string;
      whitelist: string;
    };
    whitelist_entries: string[];
    block_entries: string[];
    blacklist_entries: string[];
    ports_aliases: Record<string, string>;
    port_entries: Record<string, number[]>;
  };

  type FirewallRule = {
    uuid: string;
    description: string;
    enabled: boolean;
    action: string;
    interface: string;
    source_net?: string;
    type?: string;
  };

  let firewalls: FirewallConfig[] = [];
  let selectedFirewallId = '';
  let aliases: FirewallAliases | null = null;
  let rules: FirewallRule[] = [];
  let loading = false;
  let installingRules = false;
  let error: string | null = null;
  let message: string | null = null;

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
      error = err instanceof Error ? err.message : 'No se pudieron cargar firewalls';
    }
  };

  const loadAliases = async () => {
    if (!selectedFirewallId) {
      aliases = null;
      return;
    }
    loading = true;
    error = null;
    try {
      aliases = await requestJson<FirewallAliases>(
        `/api/firewalls/${selectedFirewallId}/aliases`
      );
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudieron cargar alias';
    } finally {
      loading = false;
    }
  };

  const loadRules = async () => {
    if (!selectedFirewallId) {
      rules = [];
      return;
    }
    loading = true;
    error = null;
    try {
      const payload = await requestJson<{ rules: FirewallRule[] }>(
        `/api/firewalls/${selectedFirewallId}/rules`
      );
      rules = payload.rules || [];
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudieron cargar reglas';
    } finally {
      loading = false;
    }
  };

  const toggleRule = async (rule: FirewallRule) => {
    if (!selectedFirewallId) {
      return;
    }
    message = null;
    try {
      await requestJson(
        `/api/firewalls/${selectedFirewallId}/rules/${rule.uuid}/toggle?enabled=${
          rule.enabled ? 'false' : 'true'
        }`,
        { method: 'POST' }
      );
      await loadRules();
    } catch (err) {
      message = err instanceof Error ? err.message : 'No se pudo cambiar la regla';
    }
  };

  const deleteRule = async (rule: FirewallRule) => {
    if (!selectedFirewallId) {
      return;
    }
    if (!confirm(`Eliminar regla ${rule.description}?`)) {
      return;
    }
    message = null;
    try {
      await requestJson(`/api/firewalls/${selectedFirewallId}/rules/${rule.uuid}`, {
        method: 'DELETE'
      });
      await loadRules();
    } catch (err) {
      message = err instanceof Error ? err.message : 'No se pudo eliminar la regla';
    }
  };

  const setupFirewallRules = async () => {
    if (!selectedFirewallId) {
      message = 'Selecciona un firewall';
      return;
    }

    installingRules = true;
    message = null;
    try {
      const payload = await requestJson<{ message?: string }>(
        `/api/firewalls/${selectedFirewallId}/setup`,
        { method: 'POST' }
      );
      message = payload.message || 'Reglas instaladas/actualizadas correctamente';
      await Promise.all([loadAliases(), loadRules()]);
    } catch (err) {
      message = err instanceof Error ? err.message : 'No se pudieron instalar/actualizar reglas';
    } finally {
      installingRules = false;
    }
  };

  const onFirewallChange = () => {
    loadAliases();
    loadRules();
  };

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadFirewalls().then(() => {
      if (selectedFirewallId) {
        loadAliases();
        loadRules();
      }
    });
  });
</script>

<section class="page-header">
  <div class="badge">Firewall</div>
  <h1>Alias y reglas</h1>
  <p>Consulta entradas sincronizadas y administra reglas de Mimosa en el firewall.</p>
</section>

{#if error}
  <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

<div class="section">
  <div class="surface" style="padding: 18px;">
    <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px;">
      <div>
        <div class="badge">Seleccion</div>
        <h3 style="margin-top: 12px;">Firewall activo</h3>
      </div>
      <div style="display: flex; gap: 12px;">
        <select bind:value={selectedFirewallId} on:change={onFirewallChange}>
          <option value="">Seleccionar</option>
          {#each firewalls as fw}
            <option value={fw.id}>{fw.name} ({fw.type})</option>
          {/each}
        </select>
        <button class="ghost" on:click={onFirewallChange}>Actualizar</button>
      </div>
    </div>
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Alias</div>
    <h3 style="margin-top: 12px;">Entradas sincronizadas</h3>

    {#if loading}
      <div style="margin-top: 12px;">Cargando alias...</div>
    {:else if !aliases}
      <div style="margin-top: 12px;">Selecciona un firewall.</div>
    {:else}
      <div class="card-grid" style="margin-top: 16px;">
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Temporal ({aliases.aliases.temporal})</strong>
          <div style="margin-top: 10px; max-height: 200px; overflow: auto;">
            <table class="table table-responsive">
              <thead>
                <tr><th>IP</th></tr>
              </thead>
              <tbody>
                {#if aliases.block_entries.length === 0}
                  <tr><td>Sin entradas.</td></tr>
                {:else}
                  {#each aliases.block_entries as entry}
                    <tr>
                      <td data-label="IP">
                        {#if isIpTarget(entry)}
                          <a class="ip-link" href={ipHref(entry)}>{entry}</a>
                        {:else}
                          {entry}
                        {/if}
                      </td>
                    </tr>
                  {/each}
                {/if}
              </tbody>
            </table>
          </div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Blacklist ({aliases.aliases.blacklist})</strong>
          <div style="margin-top: 10px; max-height: 200px; overflow: auto;">
            <table class="table table-responsive">
              <thead>
                <tr><th>IP</th></tr>
              </thead>
              <tbody>
                {#if aliases.blacklist_entries.length === 0}
                  <tr><td>Sin entradas.</td></tr>
                {:else}
                  {#each aliases.blacklist_entries as entry}
                    <tr>
                      <td data-label="IP">
                        {#if isIpTarget(entry)}
                          <a class="ip-link" href={ipHref(entry)}>{entry}</a>
                        {:else}
                          {entry}
                        {/if}
                      </td>
                    </tr>
                  {/each}
                {/if}
              </tbody>
            </table>
          </div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Whitelist ({aliases.aliases.whitelist})</strong>
          <div style="margin-top: 10px; max-height: 200px; overflow: auto;">
            <table class="table table-responsive">
              <thead>
                <tr><th>Entry</th></tr>
              </thead>
              <tbody>
                {#if aliases.whitelist_entries.length === 0}
                  <tr><td>Sin entradas.</td></tr>
                {:else}
                  {#each aliases.whitelist_entries as entry}
                    <tr>
                      <td data-label="Entry">
                        {#if isIpTarget(entry)}
                          <a class="ip-link" href={ipHref(entry)}>{entry}</a>
                        {:else}
                          {entry}
                        {/if}
                      </td>
                    </tr>
                  {/each}
                {/if}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="surface" style="padding: 12px; border: 1px solid var(--border); margin-top: 16px;">
        <strong>Alias de puertos</strong>
        <div style="margin-top: 10px; max-height: 220px; overflow: auto;">
          <table class="table table-responsive">
            <thead>
              <tr>
                <th>Protocolo</th>
                <th>Alias</th>
                <th>Puertos</th>
              </tr>
            </thead>
            <tbody>
              {#if Object.keys(aliases.port_entries || {}).length === 0}
                <tr><td colspan="3">Sin datos.</td></tr>
              {:else}
                {#each Object.entries(aliases.port_entries || {}) as entry}
                  <tr>
                    <td data-label="Protocolo">{entry[0].toUpperCase()}</td>
                    <td data-label="Alias">{aliases.ports_aliases?.[entry[0]] || '-'}</td>
                    <td data-label="Puertos">{entry[1].join(', ') || '-'}</td>
                  </tr>
                {/each}
            {/if}
            </tbody>
          </table>
        </div>
      </div>
    {/if}
  </div>

  <div class="surface" style="padding: 18px;">
    <div class="badge">Reglas</div>
    <h3 style="margin-top: 12px;">Reglas de Mimosa</h3>
    <div style="margin-top: 10px; display: flex; gap: 10px; flex-wrap: wrap;">
      <button class="ghost" on:click={setupFirewallRules} disabled={installingRules || !selectedFirewallId}>
        {installingRules ? 'Aplicando...' : 'Instalar/actualizar reglas'}
      </button>
      <button class="ghost" on:click={loadRules} disabled={loading || !selectedFirewallId}>
        Refrescar reglas
      </button>
    </div>
    {#if message}
      <div style="color: var(--warning); font-size: 12px; margin-top: 6px;">{message}</div>
    {/if}
    <div style="margin-top: 12px; overflow-x: auto;">
      <table class="table table-responsive">
        <thead>
          <tr>
            <th>Descripcion</th>
            <th>Estado</th>
            <th>Tipo</th>
            <th>Interfaz</th>
            <th>Accion</th>
            <th>Origen</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#if rules.length === 0}
            <tr><td colspan="7">Sin reglas.</td></tr>
          {:else}
            {#each rules as rule}
              <tr>
                <td data-label="Descripcion">{rule.description}</td>
                <td data-label="Estado">
                  <span class="tag" style="color: {rule.enabled ? 'var(--success)' : 'var(--warning)'};">
                    {rule.enabled ? 'Activa' : 'Inactiva'}
                  </span>
                </td>
                <td data-label="Tipo">{rule.type || '-'}</td>
                <td data-label="Interfaz">{rule.interface}</td>
                <td data-label="Accion">{rule.action}</td>
                <td data-label="Origen">{rule.source_net || '-'}</td>
                <td data-label="Control">
                  <div style="display: flex; gap: 8px;">
                    <button class="ghost" on:click={() => toggleRule(rule)}>
                      {rule.enabled ? 'Desactivar' : 'Activar'}
                    </button>
                    <button class="ghost" on:click={() => deleteRule(rule)}>Eliminar</button>
                  </div>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
  </div>
</div>
