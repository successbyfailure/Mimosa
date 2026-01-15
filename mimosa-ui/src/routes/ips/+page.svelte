<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type IpProfile = {
    ip: string;
    geo?: string | null;
    whois?: string | null;
    reverse_dns?: string | null;
    first_seen: string;
    last_seen: string;
    enriched_at?: string | null;
    offenses: number;
    blocks: number;
    // Campos de clasificación
    ip_type?: string | null;
    ip_type_confidence?: number | null;
    ip_type_source?: string | null;
    ip_type_provider?: string | null;
    isp?: string | null;
    org?: string | null;
    asn?: string | null;
    is_proxy?: boolean;
    is_mobile?: boolean;
    is_hosting?: boolean;
  };

  // Configuración de tipos de IP
  const ipTypeConfig: Record<string, { label: string; color: string; bg: string }> = {
    datacenter: { label: 'DC', color: 'var(--warning)', bg: 'rgba(251, 191, 36, 0.15)' },
    residential: { label: 'RES', color: 'var(--success)', bg: 'rgba(74, 222, 128, 0.15)' },
    governmental: { label: 'GOV', color: 'var(--accent)', bg: 'rgba(56, 189, 248, 0.15)' },
    educational: { label: 'EDU', color: 'var(--accent)', bg: 'rgba(56, 189, 248, 0.15)' },
    corporate: { label: 'CORP', color: 'var(--text)', bg: 'rgba(255, 255, 255, 0.1)' },
    mobile: { label: 'MOB', color: 'var(--muted)', bg: 'rgba(148, 163, 184, 0.15)' },
    proxy: { label: 'PROXY', color: 'var(--danger)', bg: 'rgba(248, 113, 113, 0.15)' },
    unknown: { label: '?', color: 'var(--muted)', bg: 'rgba(148, 163, 184, 0.1)' }
  };

  const getTypeConfig = (type?: string | null) => {
    return ipTypeConfig[type || 'unknown'] || ipTypeConfig.unknown;
  };

  let profiles: IpProfile[] = [];
  let loading = false;
  let error: string | null = null;
  let limit = 100;
  let query = '';
  let filterType = '';
  let sortKey: 'ip' | 'reverse_dns' | 'offenses' | 'blocks' | 'last_seen' | 'ip_type' = 'last_seen';
  let sortDir: 'asc' | 'desc' = 'desc';
  let sortedProfiles: IpProfile[] = [];

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

  const loadProfiles = async () => {
    loading = true;
    error = null;
    try {
      profiles = await requestJson<IpProfile[]>(`/api/ips?limit=${limit}`);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const refreshProfile = async (profile: IpProfile) => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      await requestJson(`/api/ips/${profile.ip}/refresh`, { method: 'POST' });
      actionMessage = `Perfil actualizado: ${profile.ip}`;
      await loadProfiles();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo refrescar';
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

  const parseGeoMeta = (raw?: string | null) => {
    if (!raw) {
      return { country: '', code: '' };
    }
    try {
      const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
      if (parsed && typeof parsed === 'object') {
        return {
          country: parsed.country || '',
          code: (parsed.country_code || parsed.countryCode || '').toUpperCase()
        };
      }
    } catch (err) {
      return { country: '', code: '' };
    }
    return { country: '', code: '' };
  };

  const ipHref = (ip: string) => `/ips/${encodeURIComponent(ip)}`;

  const countryFlag = (code?: string) => {
    if (!code || code.length !== 2) {
      return '—';
    }
    const base = 0x1f1e6;
    const first = code.charCodeAt(0) - 65 + base;
    const second = code.charCodeAt(1) - 65 + base;
    return String.fromCodePoint(first, second);
  };

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      return;
    }
    sortKey = key;
    sortDir = 'asc';
  };

  $: filtered = profiles.filter((profile) => {
    // Filtro por tipo
    if (filterType && (profile.ip_type || 'unknown') !== filterType) {
      return false;
    }
    // Filtro por búsqueda
    const needle = query.trim().toLowerCase();
    if (!needle) {
      return true;
    }
    return [profile.ip, profile.geo || '', profile.reverse_dns || '', profile.ip_type || '']
      .join(' ')
      .toLowerCase()
      .includes(needle);
  });

  $: sortedProfiles = [...filtered].sort((a, b) => {
    if (sortKey === 'offenses' || sortKey === 'blocks') {
      return (a[sortKey] || 0) - (b[sortKey] || 0);
    }
    if (sortKey === 'last_seen') {
      return Date.parse(a.last_seen) - Date.parse(b.last_seen);
    }
    if (sortKey === 'ip_type') {
      const av = (a.ip_type || 'unknown').toLowerCase();
      const bv = (b.ip_type || 'unknown').toLowerCase();
      return av.localeCompare(bv);
    }
    const av = (a[sortKey] || '').toString().toLowerCase();
    const bv = (b[sortKey] || '').toString().toLowerCase();
    return av.localeCompare(bv, undefined, { numeric: true });
  });

  $: if (sortDir === 'desc') {
    sortedProfiles = sortedProfiles.reverse();
  }

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadProfiles();
  });
</script>

<section class="page-header">
  <div class="badge">IPs</div>
  <h1>Perfiles de IP</h1>
  <p>Enriquecimiento, historico de ofensas y bloqueos.</p>
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
      <div class="grow">
        <input placeholder="Buscar por IP, DNS o tipo" bind:value={query} />
      </div>
      <div class="compact">
        <select bind:value={filterType} aria-label="Filtrar por tipo">
          <option value="">Todos los tipos</option>
          <option value="datacenter">Datacenter</option>
          <option value="residential">Residencial</option>
          <option value="governmental">Gubernamental</option>
          <option value="educational">Educativo</option>
          <option value="corporate">Corporativo</option>
          <option value="mobile">Móvil</option>
          <option value="proxy">Proxy/VPN</option>
          <option value="unknown">Desconocido</option>
        </select>
      </div>
      <div class="compact">
        <input type="number" min="10" step="10" bind:value={limit} aria-label="Limite" />
      </div>
      <button class="ghost" on:click={loadProfiles}>Recargar</button>
    </div>

    <div style="margin-top: 16px; overflow-x: auto;">
      <table class="table table-responsive table-prominent">
        <thead>
          <tr>
            <th on:click={() => toggleSort('ip')}>IP</th>
            <th on:click={() => toggleSort('ip_type')}>Tipo</th>
            <th>Pais</th>
            <th on:click={() => toggleSort('reverse_dns')}>Reverse DNS</th>
            <th on:click={() => toggleSort('offenses')}>Ofensas</th>
            <th on:click={() => toggleSort('blocks')}>Bloqueos</th>
            <th on:click={() => toggleSort('last_seen')}>Ultimo visto</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#if loading}
            <tr>
              <td colspan="8">Cargando perfiles...</td>
            </tr>
          {:else if sortedProfiles.length === 0}
            <tr>
              <td colspan="8">Sin perfiles.</td>
            </tr>
          {:else}
            {#each sortedProfiles as profile}
              {@const geo = parseGeoMeta(profile.geo)}
              {@const typeConf = getTypeConfig(profile.ip_type)}
              <tr>
                <td data-label="IP">
                  <a class="ip-link" href={ipHref(profile.ip)}>{profile.ip}</a>
                </td>
                <td data-label="Tipo">
                  <span
                    class="ip-type-badge"
                    style="color: {typeConf.color}; background: {typeConf.bg};"
                    title="{profile.ip_type || 'unknown'}{profile.is_proxy ? ' +VPN' : ''}{profile.is_mobile ? ' +MOB' : ''}"
                  >
                    {typeConf.label}{#if profile.is_proxy}<span class="badge-extra">+VPN</span>{/if}
                  </span>
                </td>
                <td data-label="Pais">{countryFlag(geo.code)} {geo.country || '-'}</td>
                <td data-label="Reverse DNS">{profile.reverse_dns || '-'}</td>
                <td data-label="Ofensas">{profile.offenses}</td>
                <td data-label="Bloqueos">{profile.blocks}</td>
                <td data-label="Ultimo visto">{formatDate(profile.last_seen)}</td>
                <td data-label="Accion">
                  <div style="display: flex; gap: 8px;">
                    <a class="ghost" href={ipHref(profile.ip)}>Ver</a>
                    <button
                      class="ghost"
                      disabled={actionLoading}
                      on:click={() => refreshProfile(profile)}
                    >
                      Refrescar
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
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
    </div>
  </div>
</div>

<style>
  .ip-type-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .badge-extra {
    font-size: 9px;
    opacity: 0.8;
    margin-left: 2px;
  }

  select {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 13px;
  }

  select:focus {
    outline: none;
    border-color: var(--accent);
  }
</style>
