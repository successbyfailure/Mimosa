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
  };

  let profiles: IpProfile[] = [];
  let loading = false;
  let error: string | null = null;
  let limit = 100;
  let query = '';
  let sortKey: 'ip' | 'reverse_dns' | 'offenses' | 'blocks' | 'last_seen' = 'last_seen';
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
    const needle = query.trim().toLowerCase();
    if (!needle) {
      return true;
    }
    return [profile.ip, profile.geo || '', profile.reverse_dns || '']
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
        <input placeholder="Buscar por IP o DNS" bind:value={query} />
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
              <td colspan="7">Cargando perfiles...</td>
            </tr>
          {:else if sortedProfiles.length === 0}
            <tr>
              <td colspan="7">Sin perfiles.</td>
            </tr>
          {:else}
            {#each sortedProfiles as profile}
              {@const geo = parseGeoMeta(profile.geo)}
              <tr>
                <td data-label="IP">
                  <a class="ip-link" href={ipHref(profile.ip)}>{profile.ip}</a>
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
