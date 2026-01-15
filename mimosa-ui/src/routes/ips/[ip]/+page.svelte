<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authStore } from '$lib/stores/auth';
  import ChartCanvas from '$lib/components/charts/ChartCanvas.svelte';
  import HeatMap from '$lib/components/charts/HeatMap.svelte';

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
  const ipTypeConfig: Record<string, { label: string; fullLabel: string; color: string; bg: string }> = {
    datacenter: { label: 'DC', fullLabel: 'Datacenter', color: 'var(--warning)', bg: 'rgba(251, 191, 36, 0.15)' },
    residential: { label: 'RES', fullLabel: 'Residencial', color: 'var(--success)', bg: 'rgba(74, 222, 128, 0.15)' },
    governmental: { label: 'GOV', fullLabel: 'Gubernamental', color: 'var(--accent)', bg: 'rgba(56, 189, 248, 0.15)' },
    educational: { label: 'EDU', fullLabel: 'Educativo', color: 'var(--accent)', bg: 'rgba(56, 189, 248, 0.15)' },
    corporate: { label: 'CORP', fullLabel: 'Corporativo', color: 'var(--text)', bg: 'rgba(255, 255, 255, 0.1)' },
    mobile: { label: 'MOB', fullLabel: 'Móvil', color: 'var(--muted)', bg: 'rgba(148, 163, 184, 0.15)' },
    proxy: { label: 'PROXY', fullLabel: 'Proxy/VPN', color: 'var(--danger)', bg: 'rgba(248, 113, 113, 0.15)' },
    unknown: { label: '?', fullLabel: 'Desconocido', color: 'var(--muted)', bg: 'rgba(148, 163, 184, 0.1)' }
  };

  const getTypeConfig = (type?: string | null) => {
    return ipTypeConfig[type || 'unknown'] || ipTypeConfig.unknown;
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
  let geoPoint: { lat: number; lon: number; count: number }[] = [];
  let geoLabel = 'Sin datos de geolocalizacion.';
  let geoFlag = '—';
  let geoLocation = '';

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
      updateGeo(profile.geo);
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

  const countryFlag = (code?: string | null) => {
    if (!code || code.length !== 2) {
      return '—';
    }
    const base = 0x1f1e6;
    const first = code.toUpperCase().charCodeAt(0) - 65 + base;
    const second = code.toUpperCase().charCodeAt(1) - 65 + base;
    return String.fromCodePoint(first, second);
  };

  const parseGeo = (value?: string | null) => {
    if (!value) {
      return null;
    }
    try {
      return JSON.parse(value) as {
        lat?: number;
        lon?: number;
        city?: string;
        region?: string;
        country?: string;
        country_code?: string;
      };
    } catch (err) {
      return null;
    }
  };

  const updateGeo = (value?: string | null) => {
    const parsed = parseGeo(value);
    if (!parsed || parsed.lat == null || parsed.lon == null) {
      geoPoint = [];
      geoLabel = 'Sin datos de geolocalizacion.';
      geoFlag = '—';
      geoLocation = '';
      return;
    }
    geoPoint = [{ lat: parsed.lat, lon: parsed.lon, count: 1 }];
    geoFlag = countryFlag(parsed.country_code);
    const parts = [parsed.city, parsed.region, parsed.country].filter(Boolean);
    geoLocation = parts.join(', ');
    geoLabel = geoLocation || 'Ubicacion registrada';
  };

  const activeDays = (value?: IpProfile | null) => {
    if (!value) {
      return '-';
    }
    const start = new Date(value.first_seen).getTime();
    const end = new Date(value.last_seen).getTime();
    if (!Number.isFinite(start) || !Number.isFinite(end)) {
      return '-';
    }
    const diff = Math.max(0, end - start);
    return Math.max(1, Math.ceil(diff / (1000 * 60 * 60 * 24)));
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
  <h1>
    {geoFlag} IP: {profile?.ip || $page.params.ip} : {profile?.offenses ?? '-'} ofensas / {profile?.blocks ?? '-'}
    bloqueos en {activeDays(profile)} días.
  </h1>
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
      {@const typeConf = getTypeConfig(profile.ip_type)}
      <div class="card-grid" style="margin-top: 16px;">
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Clasificación</strong>
          <div style="margin-top: 10px;">
            <span
              class="ip-type-badge-large"
              style="color: {typeConf.color}; background: {typeConf.bg};"
            >
              {typeConf.fullLabel}
            </span>
          </div>
          <div style="color: var(--muted); margin-top: 8px; font-size: 12px;">
            Confianza: {profile.ip_type_confidence ? Math.round(profile.ip_type_confidence * 100) : 0}%
          </div>
          <div style="color: var(--muted); font-size: 11px;">
            Fuente: {profile.ip_type_source || 'N/A'}
          </div>
          <div style="margin-top: 10px; display: flex; gap: 6px; flex-wrap: wrap;">
            {#if profile.is_hosting}
              <span class="mini-badge hosting">Hosting</span>
            {/if}
            {#if profile.is_proxy}
              <span class="mini-badge proxy">Proxy/VPN</span>
            {/if}
            {#if profile.is_mobile}
              <span class="mini-badge mobile">Móvil</span>
            {/if}
          </div>
          <div style="margin-top: 10px; color: var(--muted); font-size: 11px;">
            <div>ISP: {profile.isp || '-'}</div>
            <div>Org: {profile.org || '-'}</div>
            <div>ASN: {profile.asn || '-'}</div>
          </div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Geo</strong>
          <div style="color: var(--muted); margin-top: 6px;">
            {geoFlag} {geoLocation || 'Sin datos'}
          </div>
          <HeatMap points={geoPoint} height={160} emptyMessage={geoLabel} />
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Reverse DNS</strong>
          <div style="color: var(--muted); margin-top: 6px;">{profile.reverse_dns || '-'}</div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Ofensas</strong>
          <div class="stat-value" style="margin-top: 6px;">{profile.offenses}</div>
        </div>
        <div class="surface" style="padding: 12px; border: 1px solid var(--border);">
          <strong>Bloqueos</strong>
          <div class="stat-value" style="margin-top: 6px;">{profile.blocks}</div>
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
            Primera deteccion: {formatDate(profile.first_seen)}
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
    <table class="table table-responsive" style="margin-top: 12px;">
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
              <td data-label="ID">{offense.id}</td>
              <td data-label="Plugin">{offense.plugin || 'manual'}</td>
              <td data-label="Severidad">{offense.severity || '-'}</td>
              <td data-label="Descripcion">{offense.description_clean || offense.description}</td>
              <td data-label="Fecha">{formatDate(offense.created_at)}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>

  <div class="surface" style="padding: 18px; overflow-x: auto;">
    <div class="badge">Bloqueos</div>
    <table class="table table-responsive" style="margin-top: 12px;">
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
              <td data-label="ID">{block.id}</td>
              <td data-label="Motivo">{block.reason || '-'}</td>
              <td data-label="Fuente">{block.source || '-'}</td>
              <td data-label="Creado">{formatDate(block.created_at)}</td>
              <td data-label="Expira">{formatDate(block.expires_at)}</td>
              <td data-label="Estado">{block.active ? 'Activo' : 'Inactivo'}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .ip-type-badge-large {
    display: inline-block;
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .mini-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
  }

  .mini-badge.hosting {
    background: rgba(251, 191, 36, 0.18);
    color: var(--warning);
  }

  .mini-badge.proxy {
    background: rgba(248, 113, 113, 0.18);
    color: var(--danger);
  }

  .mini-badge.mobile {
    background: rgba(148, 163, 184, 0.18);
    color: var(--muted);
  }
</style>
