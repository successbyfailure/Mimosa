<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authStore } from '$lib/stores/auth';
  import ChartCanvas from '$lib/components/charts/ChartCanvas.svelte';

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

  type Offense = {
    id: number;
    source_ip: string;
    description: string;
    description_clean?: string;
    plugin?: string | null;
    severity?: string | null;
    created_at: string;
    context?: Record<string, any> | null;
  };

  type BlockEntry = {
    id: number;
    ip: string;
    reason: string;
    created_at: string;
    expires_at?: string | null;
    active: boolean;
    source?: string;
  };

  let profile: IpProfile | null = null;
  let offenses: Offense[] = [];
  let blocks: BlockEntry[] = [];
  let loading = false;
  let error: string | null = null;
  let actionMessage: string | null = null;
  let actionError: string | null = null;
  let actionLoading = false;

  let offenseLabels: string[] = [];
  let offenseValues: number[] = [];
  let blockSummary = '';
  let offenseSummary = '';
  let latestBlock = '';

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

  const groupOffenses = (items: Offense[]) => {
    const grouped: Record<string, number> = {};
    for (const offense of items) {
      const contextType = offense.context?.alert_type || offense.context?.event_id;
      let key = contextType;
      if (!key && offense.description && offense.description.includes(':')) {
        const after = offense.description.split(':')[1] || '';
        key = after.trim().split(/\s+/)[0];
      }
      if (!key) {
        key = offense.context?.plugin || offense.plugin || 'desconocido';
      }
      key = (key || 'desconocido').trim();
      grouped[key] = (grouped[key] || 0) + 1;
    }
    const entries = Object.entries(grouped).sort((a, b) => b[1] - a[1]);
    offenseLabels = entries.map(([label]) => label);
    offenseValues = entries.map(([, count]) => count);
    offenseSummary = entries.map(([label, count]) => `${label}: ${count}`).join(' · ');
  };

  const groupBlocks = (items: BlockEntry[]) => {
    const grouped: Record<string, number> = {};
    for (const block of items) {
      const key = block.source || 'desconocido';
      grouped[key] = (grouped[key] || 0) + 1;
    }
    const entries = Object.entries(grouped).sort((a, b) => b[1] - a[1]);
    blockSummary = entries.map(([label, count]) => `${label}: ${count}`).join(' · ');
    latestBlock = items[0] ? formatDate(items[0].created_at) : 'sin registros';
  };

  const loadProfile = async () => {
    loading = true;
    error = null;
    try {
      const ip = $page.params.ip;
      const data = await requestJson<{
        profile: IpProfile;
        offenses: Offense[];
        blocks: BlockEntry[];
      }>(`/api/ips/${ip}`);
      profile = data.profile;
      offenses = data.offenses;
      blocks = data.blocks;
      groupOffenses(offenses);
      groupBlocks(blocks);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const refreshProfile = async () => {
    if (!profile) {
      return;
    }
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      await requestJson(`/api/ips/${profile.ip}/refresh`, { method: 'POST' });
      actionMessage = 'Perfil actualizado';
      await loadProfile();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo refrescar';
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

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadProfile();
  });
</script>

<section class="page-header">
  <div class="badge">IP</div>
  <h1>Perfil {profile?.ip || $page.params.ip}</h1>
  <p>Detalle de actividad y enriquecimiento.</p>
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
        <div class="badge">Perfil</div>
        <h3 style="margin-top: 12px;">Resumen</h3>
      </div>
      <div style="display: flex; gap: 8px;">
        <a class="ghost" href="/ips">Volver</a>
        <button class="ghost" disabled={actionLoading} on:click={refreshProfile}>
          Refrescar
        </button>
      </div>
    </div>
    {#if loading || !profile}
      <div style="margin-top: 12px;">Cargando perfil...</div>
    {:else}
      <div class="card-grid" style="margin-top: 16px;">
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Geo</strong>
          <div style="color: var(--muted); margin-top: 6px;">{profile.geo || '-'}</div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Reverse DNS</strong>
          <div style="color: var(--muted); margin-top: 6px;">{profile.reverse_dns || '-'}</div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Ofensas</strong>
          <div style="color: var(--muted); margin-top: 6px;">{profile.offenses}</div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Bloqueos</strong>
          <div style="color: var(--muted); margin-top: 6px;">{profile.blocks}</div>
        </div>
      </div>
      <div style="margin-top: 12px; color: var(--muted); font-size: 12px;">
        Primero: {formatDate(profile.first_seen)} - Ultimo: {formatDate(profile.last_seen)}
      </div>
      <div class="split" style="margin-top: 16px; gap: 16px;">
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Estadisticas rapidas</strong>
          <div style="color: var(--muted); margin-top: 6px;">
            {offenses.length} ofensas · {blocks.length} bloqueos
          </div>
          <div style="color: var(--muted); margin-top: 6px;">
            Ultimo bloqueo: {latestBlock}
          </div>
          <div style="color: var(--muted); margin-top: 6px;">
            Tipos de bloqueo: {blockSummary || 'Sin bloqueos registrados'}
          </div>
          <div style="color: var(--muted); margin-top: 6px;">
            Tipos de ofensa: {offenseSummary || 'Sin ofensas registradas'}
          </div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Distribucion de ofensas</strong>
          {#if offenseLabels.length === 0}
            <div style="margin-top: 12px; color: var(--muted);">Sin datos para graficar.</div>
          {:else}
            <ChartCanvas
              labels={offenseLabels}
              data={offenseValues}
              label="Ofensas"
              type="doughnut"
              showLegend={true}
            />
          {/if}
        </div>
      </div>
    {/if}
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

  <div class="surface" style="padding: 18px; overflow-x: auto;">
    <div class="badge">Ofensas</div>
    <table class="table" style="margin-top: 12px;">
      <thead>
        <tr>
          <th>ID</th>
          <th>Plugin</th>
          <th>Severidad</th>
          <th>Descripcion</th>
          <th>Fecha</th>
        </tr>
      </thead>
      <tbody>
        {#if offenses.length === 0}
          <tr>
            <td colspan="5">Sin ofensas.</td>
          </tr>
        {:else}
          {#each offenses as offense}
            <tr>
              <td>{offense.id}</td>
              <td>{offense.plugin || 'manual'}</td>
              <td>{offense.severity || '-'}</td>
              <td>{offense.description_clean || offense.description}</td>
              <td>{formatDate(offense.created_at)}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>

  <div class="surface" style="padding: 18px; overflow-x: auto;">
    <div class="badge">Bloqueos</div>
    <table class="table" style="margin-top: 12px;">
      <thead>
        <tr>
          <th>ID</th>
          <th>Motivo</th>
          <th>Fuente</th>
          <th>Creado</th>
          <th>Expira</th>
          <th>Estado</th>
        </tr>
      </thead>
      <tbody>
        {#if blocks.length === 0}
          <tr>
            <td colspan="6">Sin bloqueos.</td>
          </tr>
        {:else}
          {#each blocks as block}
            <tr>
              <td>{block.id}</td>
              <td>{block.reason || '-'}</td>
              <td>{block.source || '-'}</td>
              <td>{formatDate(block.created_at)}</td>
              <td>{formatDate(block.expires_at)}</td>
              <td>{block.active ? 'Activo' : 'Inactivo'}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</div>
