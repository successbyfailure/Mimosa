<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { authStore } from '$lib/stores/auth';
  import StatCard from '$lib/components/dashboard/StatCard.svelte';
  import ChartCanvas from '$lib/components/charts/ChartCanvas.svelte';
  import HeatMap from '$lib/components/charts/HeatMap.svelte';

  type TimelineEntry = {
    bucket: string;
    count: number;
  };

  type StatsPayload = {
    offenses: {
      total: number;
      last_7d: number;
      last_24h: number;
      last_1h: number;
      timeline: {
        '7d': TimelineEntry[];
        '24h': TimelineEntry[];
        '1h': TimelineEntry[];
      };
    };
    blocks: {
      current: number;
      total: number;
      last_7d: number;
      last_24h: number;
      last_1h: number;
      timeline: {
        '7d': TimelineEntry[];
        '24h': TimelineEntry[];
        '1h': TimelineEntry[];
      };
    };
  };

  type CountryEntry = {
    country: string;
    country_code?: string | null;
    blocks: number;
  };

  type PublicCountryEntry = {
    country: string;
    country_code?: string | null;
    offenses: number;
  };

  type HeatPoint = {
    lat: number;
    lon: number;
    count: number;
  };

  type Plugin = {
    name: string;
    enabled: boolean;
    config: Record<string, unknown>;
  };

  type ProxyStats = {
    top_domains: { domain: string; hits: number }[];
  };

  type PortStats = {
    top_ports: { protocol: string; port: number; hits: number }[];
  };

  type MimosaNpmStats = {
    total: number;
    sample: number;
    top_domains: { domain: string; count: number }[];
    top_paths: { path: string; count: number }[];
    top_status_codes: { status: string; count: number }[];
  };

  type LiveItem = {
    kind: 'offense' | 'block';
    ip: string;
    detail: string;
    at: string;
    plugin?: string | null;
  };

  type PublicOffense = {
    source_ip: string;
    description: string;
    description_clean?: string | null;
    created_at: string;
    plugin?: string | null;
    host?: string | null;
    path?: string | null;
    severity?: string | null;
    country_code?: string | null;
    country?: string | null;
    lat?: number | null;
    lon?: number | null;
  };

  type OffenseTypeEntry = {
    type: string;
    count: number;
  };

  type TopIp = {
    ip: string;
    offenses: number;
    blocks: number;
    score: number;
    last_seen: string;
  };

  type ExpiringBlock = {
    ip: string;
    minutes_left: number;
    reason?: string | null;
    reason_text?: string | null;
    reason_plugin?: string | null;
    reason_counts?: {
      offenses_total?: number | null;
      offenses_1h?: number | null;
      blocks_total?: number | null;
    };
  };

  type BlockReason = {
    reason: string;
    count: number;
    last_at: string;
    reason_text?: string | null;
    reason_plugin?: string | null;
  };

  type FirewallHealth = {
    id: string;
    name: string;
    type: string;
    available: boolean;
    latency_ms?: number | null;
    error?: string | null;
  };

  type PluginHealth = {
    name: string;
    enabled: boolean;
    last_24h: number;
    last_event_at?: string | null;
  };

  type ReasonCounts = {
    offenses_total?: number | null;
    offenses_1h?: number | null;
    blocks_total?: number | null;
  };

  type RecentOffense = {
    source_ip: string;
    description: string;
    description_clean?: string | null;
    created_at: string;
    plugin?: string | null;
    reason_text?: string | null;
    reason_plugin?: string | null;
    reason_counts?: ReasonCounts;
    lat?: number | null;
    lon?: number | null;
    country?: string | null;
    country_code?: string | null;
  };

  type RecentBlock = {
    ip: string;
    reason: string;
    created_at: string;
    reason_text?: string | null;
    reason_plugin?: string | null;
    reason_counts?: ReasonCounts;
  };

  type DashboardTab = 'overview' | 'map' | 'insights' | 'health' | 'plugins';

  const tabs: { value: DashboardTab; label: string }[] = [
    { value: 'map', label: 'Mapa' },
    { value: 'overview', label: 'Detalle' },
    { value: 'insights', label: 'Insights' },
    { value: 'health', label: 'Salud' },
    { value: 'plugins', label: 'Plugins' }
  ];

  let activeTab: DashboardTab = 'map';

  let stats: StatsPayload | null = null;
  let error: string | null = null;
  let loading = false;

  type WindowKey = '1h' | '24h' | '7d';
  const windowOptions: { value: WindowKey; label: string }[] = [
    { value: '7d', label: '7d' },
    { value: '24h', label: '24h' },
    { value: '1h', label: '1h' }
  ];

  let offenseWindow: WindowKey = '7d';
  let blockWindow: WindowKey = '7d';

  let offenseLabels: string[] = [];
  let offenseValues: number[] = [];
  let blockLabels: string[] = [];
  let blockValues: number[] = [];
  let ratioLabels: string[] = [];
  let ratioValues: number[] = [];

  let countryEntries: CountryEntry[] = [];
  let countryLabels: string[] = [];
  let countryValues: number[] = [];
  let heatPoints: HeatPoint[] = [];
  let heatmapMessage = 'Sin datos de geolocalizacion.';

  type HeatmapWindow = 'current' | '24h' | 'week' | 'month' | 'total';
  const heatmapOptions: { value: HeatmapWindow; label: string }[] = [
    { value: 'current', label: 'Actual' },
    { value: '24h', label: '24h' },
    { value: 'week', label: 'Semana' },
    { value: 'month', label: 'Mes' },
    { value: 'total', label: 'Total' }
  ];
  let heatmapWindow: HeatmapWindow = 'total';

  type PublicWindow = '24h' | 'week' | 'month' | 'total';
  const publicWindowOptions: { value: PublicWindow; label: string }[] = [
    { value: '24h', label: '24h' },
    { value: 'week', label: 'Semana' },
    { value: 'month', label: 'Mes' },
    { value: 'total', label: 'Total' }
  ];
  let publicWindow: PublicWindow = '24h';

  const ipHref = (ip: string) => `/ips/${encodeURIComponent(ip)}`;

  let plugins: Plugin[] = [];
  let proxyStats: ProxyStats | null = null;
  let portStats: PortStats | null = null;
  let mimosanpmStats: MimosaNpmStats | null = null;
  let proxyLabels: string[] = [];
  let proxyValues: number[] = [];
  let portLabels: string[] = [];
  let portValues: number[] = [];
  let npmDomainLabels: string[] = [];
  let npmDomainValues: number[] = [];
  let npmPathLabels: string[] = [];
  let npmPathValues: number[] = [];
  let npmStatusLabels: string[] = [];
  let npmStatusValues: number[] = [];

  let liveFeedRaw: LiveItem[] = [];
  let liveFeed: LiveItem[] = [];
  let liveFilter = '';
  let wsStatus = 'disconnected';
  let lastLiveAt: string | null = null;
  let ws: WebSocket | null = null;
  let reconnectTimer: number | null = null;

  let topIps: TopIp[] = [];
  let expiringBlocks: ExpiringBlock[] = [];
  let blockReasons: BlockReason[] = [];
  let firewallsHealth: FirewallHealth[] = [];
  let pluginsHealth: PluginHealth[] = [];
  let insightsError: string | null = null;
  let latestOffenses: RecentOffense[] = [];
  let latestBlocks: RecentBlock[] = [];
  let mapAttackOrigins: { lat: number; lon: number }[] = [];
  let mapAttackKey = 0;
  let mapLatestEventMs: number | null = null;

  let statsInterval: number | undefined;
  let insightInterval: number | undefined;
  let pluginInterval: number | undefined;
  let heatmapInterval: number | undefined;
  let mapActivityInterval: number | undefined;
  let publicFeedInterval: number | undefined;
  let publicGeoInterval: number | undefined;
  let publicTypesInterval: number | undefined;

  let isPublic = false;
  let publicFeed: PublicOffense[] = [];
  let publicHeatPoints: HeatPoint[] = [];
  let publicHeatmapMessage = 'Sin datos de geolocalizacion.';
  let publicCountries: PublicCountryEntry[] = [];
  let publicCountryLabels: string[] = [];
  let publicCountryValues: number[] = [];
  let publicTypes: OffenseTypeEntry[] = [];
  let publicTypeLabels: string[] = [];
  let publicTypeValues: number[] = [];
  let publicLastAt: string | null = null;
  let publicError: string | null = null;
  let publicLatestEventAt: string | null = null;
  let publicLatestEventMs: number | null = null;
  let publicPulseKey = 0;
  let publicAttackKey = 0;
  let publicAttackOrigins: { lat: number; lon: number }[] = [];
  let mimosaLocation: { lat: number; lon: number } | null = null;

  let authInitialized = false;
  let publicInitialized = false;

  const formatBucket = (bucket: string) => {
    const parts = bucket.split(' ');
    return parts.length > 1 ? parts[1] : bucket;
  };

  const getTimeline = (
    timeline: StatsPayload['offenses']['timeline'],
    key: WindowKey
  ) => {
    return timeline[key] || timeline['24h'];
  };

  const updateStatsView = (payload: StatsPayload) => {
    const offenseTimeline = getTimeline(payload.offenses.timeline, offenseWindow);
    const blockTimeline = getTimeline(payload.blocks.timeline, blockWindow);
    offenseLabels = offenseTimeline.map((entry) => formatBucket(entry.bucket));
    offenseValues = offenseTimeline.map((entry) => entry.count);
    blockLabels = blockTimeline.map((entry) => formatBucket(entry.bucket));
    blockValues = blockTimeline.map((entry) => entry.count);

    const ratioOffense = payload.offenses.timeline['24h'] || [];
    const ratioBlocks = payload.blocks.timeline['24h'] || [];
    ratioLabels = ratioOffense.map((entry) => formatBucket(entry.bucket));
    ratioValues = ratioOffense.map((entry, index) => {
      const offenseCount = entry.count;
      const blockCount = ratioBlocks[index]?.count ?? 0;
      if (!blockCount) {
        return 0;
      }
      return Number((offenseCount / blockCount).toFixed(2));
    });
  };

  const applyStats = (payload: StatsPayload) => {
    stats = payload;
    updateStatsView(payload);
  };

  const loadStats = async () => {
    loading = true;
    error = null;
    try {
      const response = await fetch('/api/stats', { credentials: 'include' });
      if (!response.ok) {
        throw new Error('No se pudo cargar el estado');
      }
      const payload = (await response.json()) as StatsPayload;
      applyStats(payload);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error desconocido';
    } finally {
      loading = false;
    }
  };

  const loadHeatmap = async () => {
    heatmapMessage = 'Cargando datos...';
    try {
      const [heatResponse, countryResponse] = await Promise.all([
        fetch(`/api/offenses/heatmap?window=${heatmapWindow}&limit=200`, {
          credentials: 'include'
        }),
        fetch(`/api/offenses/blocks_by_country?window=${heatmapWindow}&limit=8`, {
          credentials: 'include'
        })
      ]);
      if (heatResponse.ok) {
        const payload = (await heatResponse.json()) as {
          points: HeatPoint[];
          total_profiles?: number;
          points_count?: number;
        };
        heatPoints = payload.points || [];
        if (!heatPoints.length) {
          heatmapMessage = 'Sin datos de geolocalizacion.';
        } else if (payload.points_count) {
          heatmapMessage = `Puntos: ${payload.points_count}`;
        } else {
          heatmapMessage = '';
        }
      } else {
        heatPoints = [];
        heatmapMessage = 'No se pudo cargar el mapa.';
      }
      if (countryResponse.ok) {
        const payload = (await countryResponse.json()) as { countries: CountryEntry[] };
        countryEntries = payload.countries || [];
        countryLabels = countryEntries.map((entry) => entry.country);
        countryValues = countryEntries.map((entry) => entry.blocks);
      }
    } catch (err) {
      heatPoints = [];
      heatmapMessage = 'No se pudo cargar el mapa.';
    }
  };

  const loadPublicFeed = async () => {
    try {
      const response = await fetch('/api/public/feed?limit=10');
      if (!response.ok) {
        throw new Error('No se pudo cargar el feed');
      }
      const payload = (await response.json()) as PublicOffense[];
      const nextFeed = payload.slice(0, 10);
      publicFeed = nextFeed;
      const latest = nextFeed[0]?.created_at;
      const latestMs = latest ? new Date(latest).getTime() : null;
      const attackOrigins: { lat: number; lon: number }[] = [];
      if (latestMs && latestMs !== publicLatestEventMs) {
        publicPulseKey += 1;
        for (const item of nextFeed) {
          const itemMs = new Date(item.created_at).getTime();
          if (publicLatestEventMs && itemMs <= publicLatestEventMs) {
            continue;
          }
          if (item.lat == null || item.lon == null) {
            continue;
          }
          attackOrigins.push({ lat: item.lat, lon: item.lon });
        }
        if (attackOrigins.length) {
          publicAttackOrigins = attackOrigins;
          publicAttackKey += 1;
        }
        publicLatestEventAt = latest;
        publicLatestEventMs = latestMs;
      }
      publicLastAt = new Date().toISOString();
      publicError = null;
    } catch (err) {
      publicError = err instanceof Error ? err.message : 'No se pudo cargar el feed';
    }
  };

  const loadMimosaLocation = async () => {
    try {
      const response = await fetch('/api/public/mimosa_location');
      if (!response.ok) {
        return;
      }
      const payload = (await response.json()) as { lat: number | null; lon: number | null };
      if (payload.lat == null || payload.lon == null) {
        mimosaLocation = null;
        return;
      }
      mimosaLocation = { lat: payload.lat, lon: payload.lon };
    } catch (err) {
      mimosaLocation = null;
    }
  };

  const loadPublicGeo = async () => {
    publicHeatmapMessage = 'Cargando datos...';
    try {
      const [heatResponse, countryResponse] = await Promise.all([
        fetch(`/api/public/heatmap?window=${publicWindow}&limit=200`),
        fetch(`/api/public/offenses_by_country?window=${publicWindow}&limit=8`)
      ]);
      if (heatResponse.ok) {
        const payload = (await heatResponse.json()) as {
          points: HeatPoint[];
          points_count?: number;
        };
        publicHeatPoints = payload.points || [];
        if (!publicHeatPoints.length) {
          publicHeatmapMessage = 'Sin datos de geolocalizacion.';
        } else if (payload.points_count) {
          publicHeatmapMessage = `Puntos: ${payload.points_count}`;
        } else {
          publicHeatmapMessage = '';
        }
      } else {
        publicHeatPoints = [];
        publicHeatmapMessage = 'No se pudo cargar el mapa.';
      }
      if (countryResponse.ok) {
        const payload = (await countryResponse.json()) as { countries: PublicCountryEntry[] };
        publicCountries = payload.countries || [];
        publicCountryLabels = publicCountries.map((entry) => entry.country);
        publicCountryValues = publicCountries.map((entry) => entry.offenses);
      }
    } catch (err) {
      publicHeatPoints = [];
      publicHeatmapMessage = 'No se pudo cargar el mapa.';
    }
  };

  const loadPublicTypes = async () => {
    try {
      const response = await fetch(
        `/api/public/offense_types?window=${publicWindow}&limit=8&sample=500`
      );
      if (!response.ok) {
        throw new Error('No se pudo cargar tipos');
      }
      const payload = (await response.json()) as { types: OffenseTypeEntry[] };
      publicTypes = payload.types || [];
      publicTypeLabels = publicTypes.map((entry) => entry.type);
      publicTypeValues = publicTypes.map((entry) => entry.count);
    } catch (err) {
      publicTypes = [];
    }
  };

  const loadPlugins = async () => {
    try {
      const response = await fetch('/api/plugins', { credentials: 'include' });
      if (!response.ok) {
        return;
      }
      plugins = (await response.json()) as Plugin[];

      const proxy = plugins.find((item) => item.name === 'proxytrap' && item.enabled);
      const port = plugins.find((item) => item.name === 'portdetector' && item.enabled);
      const npm = plugins.find((item) => item.name === 'mimosanpm' && item.enabled);

      if (proxy) {
        const proxyResponse = await fetch('/api/plugins/proxytrap/stats', {
          credentials: 'include'
        });
        if (proxyResponse.ok) {
          proxyStats = (await proxyResponse.json()) as ProxyStats;
          proxyLabels = proxyStats.top_domains.map((entry) => entry.domain);
          proxyValues = proxyStats.top_domains.map((entry) => entry.hits);
        }
      }
      if (port) {
        const portResponse = await fetch('/api/plugins/portdetector/stats?limit=5', {
          credentials: 'include'
        });
        if (portResponse.ok) {
          portStats = (await portResponse.json()) as PortStats;
          portLabels = portStats.top_ports.map((entry) =>
            `${entry.protocol.toUpperCase()} ${entry.port}`
          );
          portValues = portStats.top_ports.map((entry) => entry.hits);
        }
      }
      if (npm) {
        const npmResponse = await fetch('/api/plugins/mimosanpm/stats?limit=5&sample=500', {
          credentials: 'include'
        });
        if (npmResponse.ok) {
          mimosanpmStats = (await npmResponse.json()) as MimosaNpmStats;
          npmDomainLabels = mimosanpmStats.top_domains.map((entry) => entry.domain);
          npmDomainValues = mimosanpmStats.top_domains.map((entry) => entry.count);
          npmPathLabels = mimosanpmStats.top_paths.map((entry) => entry.path);
          npmPathValues = mimosanpmStats.top_paths.map((entry) => entry.count);
          npmStatusLabels = mimosanpmStats.top_status_codes.map((entry) => entry.status);
          npmStatusValues = mimosanpmStats.top_status_codes.map((entry) => entry.count);
        } else {
          mimosanpmStats = null;
          npmDomainLabels = [];
          npmDomainValues = [];
          npmPathLabels = [];
          npmPathValues = [];
          npmStatusLabels = [];
          npmStatusValues = [];
        }
      } else {
        mimosanpmStats = null;
        npmDomainLabels = [];
        npmDomainValues = [];
        npmPathLabels = [];
        npmPathValues = [];
        npmStatusLabels = [];
        npmStatusValues = [];
      }
    } catch (err) {
      // opcional
    }
  };

  const fetchJson = async <T>(path: string): Promise<T> => {
    const response = await fetch(path, { credentials: 'include' });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload?.detail || 'Error en la solicitud');
    }
    return response.json() as Promise<T>;
  };

  const loadInsights = async () => {
    insightsError = null;
    const [topResult, expiringResult, reasonsResult, healthResult] = await Promise.allSettled([
      fetchJson<TopIp[]>('/api/dashboard/top_ips?limit=10'),
      fetchJson<ExpiringBlock[]>('/api/dashboard/blocks/expiring?within_minutes=60&limit=10'),
      fetchJson<BlockReason[]>('/api/dashboard/blocks/reasons?limit=10'),
      fetchJson<{ firewalls: FirewallHealth[]; plugins: PluginHealth[] }>(
        '/api/dashboard/health'
      )
    ]);

    if (topResult.status === 'fulfilled') {
      topIps = topResult.value;
    } else {
      insightsError = topResult.reason?.message || 'No se pudo cargar Top IPs.';
    }

    if (expiringResult.status === 'fulfilled') {
      expiringBlocks = expiringResult.value;
    }

    if (reasonsResult.status === 'fulfilled') {
      blockReasons = reasonsResult.value;
    }

    if (healthResult.status === 'fulfilled') {
      firewallsHealth = healthResult.value.firewalls || [];
      pluginsHealth = healthResult.value.plugins || [];
    }
  };

  const loadMapActivity = async () => {
    try {
      latestOffenses = await fetchJson<RecentOffense[]>('/api/offenses?limit=6');
      const latest = latestOffenses[0]?.created_at;
      const latestMs = latest ? new Date(latest).getTime() : null;
      const attackOrigins: { lat: number; lon: number }[] = [];
      if (latestMs && latestMs != mapLatestEventMs) {
        for (const item of latestOffenses) {
          const itemMs = new Date(item.created_at).getTime();
          if (mapLatestEventMs && itemMs <= mapLatestEventMs) {
            continue;
          }
          if (item.lat == null || item.lon == null) {
            continue;
          }
          attackOrigins.push({ lat: item.lat, lon: item.lon });
        }
        if (attackOrigins.length) {
          mapAttackOrigins = attackOrigins;
          mapAttackKey += 1;
        }
        mapLatestEventMs = latestMs;
      }
    } catch (err) {
      latestOffenses = [];
    }
    try {
      latestBlocks = await fetchJson<RecentBlock[]>('/api/blocks?include_expired=false&limit=6');
    } catch (err) {
      latestBlocks = [];
    }
  };

  const buildLiveFeed = (payload: { offenses?: any[]; blocks?: any[] }) => {
    const items: LiveItem[] = [];
    for (const offense of payload.offenses || []) {
      items.push({
        kind: 'offense',
        ip: offense.source_ip,
        detail: offense.description_clean || offense.description,
        at: offense.created_at,
        plugin: offense.plugin || offense.context?.plugin || null
      });
    }
    for (const block of payload.blocks || []) {
      items.push({
        kind: 'block',
        ip: block.ip,
        detail: `${block.action}: ${block.reason}`,
        at: block.at,
        plugin: 'blocks'
      });
    }
    items.sort((a, b) => (a.at < b.at ? 1 : -1));
    liveFeedRaw = items.slice(0, 30);
  };

  const connectLiveFeed = () => {
    if (ws) {
      ws.close();
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(`${protocol}://${window.location.host}/ws/live`);
    wsStatus = 'connecting';

    ws.onopen = () => {
      wsStatus = 'connected';
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.stats) {
          applyStats(payload.stats as StatsPayload);
        }
        if (wsStatus !== 'connected') {
          wsStatus = 'connected';
        }
        if (payload.offenses && payload.offenses.length) {
          window.dispatchEvent(new CustomEvent('mimosa:offense'));
        }
        buildLiveFeed(payload);
        lastLiveAt = payload.timestamp || new Date().toISOString();
      } catch (err) {
        // ignore
      }
    };

    ws.onclose = (event) => {
      if (event.code === 4401) {
        wsStatus = 'auth_required';
        return;
      }
      wsStatus = 'disconnected';
      if (reconnectTimer) {
        window.clearTimeout(reconnectTimer);
      }
      reconnectTimer = window.setTimeout(connectLiveFeed, 5000);
    };
  };

  const formatTime = (value: string) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleTimeString();
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

  const hasOffenseCounts = (counts?: ReasonCounts | null) => {
    if (!counts) {
      return false;
    }
    return (
      counts.offenses_total != null ||
      counts.offenses_1h != null ||
      counts.blocks_total != null
    );
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

  const handleOffenseWindowChange = (event: Event) => {
    offenseWindow = (event.target as HTMLSelectElement).value as WindowKey;
    if (stats) {
      updateStatsView(stats);
    }
  };

  const handleBlockWindowChange = (event: Event) => {
    blockWindow = (event.target as HTMLSelectElement).value as WindowKey;
    if (stats) {
      updateStatsView(stats);
    }
  };

  const handleHeatmapChange = (event: Event) => {
    heatmapWindow = (event.target as HTMLSelectElement).value as HeatmapWindow;
    loadHeatmap();
  };

  const handlePublicWindowChange = (event: Event) => {
    publicWindow = (event.target as HTMLSelectElement).value as PublicWindow;
    loadPublicGeo();
    loadPublicTypes();
  };

  const wsLabel = () => {
    if (wsStatus === 'connected') {
      return 'en vivo';
    }
    if (wsStatus === 'connecting') {
      return 'conectando';
    }
    if (wsStatus === 'auth_required') {
      return 'login requerido';
    }
    return 'offline';
  };

  const setTab = (tab: DashboardTab) => {
    activeTab = tab;
    if (tab === 'overview' && !stats) {
      loadStats();
    }
    if (tab === 'map') {
      loadHeatmap();
      loadMapActivity();
    }
    if (tab === 'insights' || tab === 'health') {
      loadInsights();
    }
    if (tab === 'plugins') {
      loadPlugins();
    }
    if (tab === 'overview' && $authStore.user && wsStatus !== 'connected' && wsStatus !== 'connecting') {
      connectLiveFeed();
    }
  };

  const stopAuth = () => {
    if (statsInterval) {
      window.clearInterval(statsInterval);
    }
    if (insightInterval) {
      window.clearInterval(insightInterval);
    }
    if (pluginInterval) {
      window.clearInterval(pluginInterval);
    }
    if (heatmapInterval) {
      window.clearInterval(heatmapInterval);
    }
    if (mapActivityInterval) {
      window.clearInterval(mapActivityInterval);
    }
    if (ws) {
      ws.close();
      ws = null;
    }
    if (reconnectTimer) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  const stopPublic = () => {
    if (publicFeedInterval) {
      window.clearInterval(publicFeedInterval);
    }
    if (publicGeoInterval) {
      window.clearInterval(publicGeoInterval);
    }
    if (publicTypesInterval) {
      window.clearInterval(publicTypesInterval);
    }
  };

  const initAuth = () => {
    stopPublic();
    authInitialized = true;
    publicInitialized = false;
    isPublic = false;
    loadStats();
    loadHeatmap();
    loadMapActivity();
    loadMimosaLocation();
    loadPlugins();
    loadInsights();
    connectLiveFeed();
    statsInterval = window.setInterval(loadStats, 60000);
    insightInterval = window.setInterval(loadInsights, 120000);
    pluginInterval = window.setInterval(loadPlugins, 120000);
    heatmapInterval = window.setInterval(loadHeatmap, 180000);
    mapActivityInterval = window.setInterval(loadMapActivity, 90000);
  };

  const initPublic = () => {
    stopAuth();
    publicInitialized = true;
    authInitialized = false;
    isPublic = true;
    loadPublicFeed();
    loadPublicGeo();
    loadPublicTypes();
    loadMimosaLocation();
    publicFeedInterval = window.setInterval(loadPublicFeed, 5000);
    publicGeoInterval = window.setInterval(loadPublicGeo, 60000);
    publicTypesInterval = window.setInterval(loadPublicTypes, 45000);
  };

  $: if ($authStore.user && wsStatus === 'auth_required') {
    connectLiveFeed();
  }

  $: liveFeed = liveFilter
    ? liveFeedRaw.filter((item) => {
        const needle = liveFilter.toLowerCase();
        if (needle === 'blocks') {
          return item.kind === 'block';
        }
        return (item.plugin || '').toLowerCase() === needle;
      })
    : liveFeedRaw;

  $: if (!$authStore.loading) {
    if ($authStore.user) {
      if (!authInitialized) {
        initAuth();
      }
    } else if (!publicInitialized) {
      initPublic();
    }
  }

  $: showOffenseCounts = latestOffenses.some((item) => hasOffenseCounts(item.reason_counts));

  onMount(() => {
    if (!$authStore.loading) {
      if ($authStore.user) {
        initAuth();
      } else {
        initPublic();
      }
    }
  });

  onDestroy(() => {
    stopAuth();
    stopPublic();
  });
</script>

{#if isPublic}
  <section class="page-header">
    <div class="badge">Publico</div>
  </section>

  {#if publicError}
    <div class="surface panel-sm" style="border-color: rgba(248, 113, 113, 0.5);">
      <strong>Error</strong>
      <div style="color: var(--muted); margin-top: 4px;">{publicError}</div>
    </div>
  {/if}

  <section class="section split public-geo">
    <div class="surface panel">
      <div class="badge">Heatmap</div>
      <div class="card-title-row">
        <h3 class="card-title">Actividad global</h3>
        <select value={publicWindow} on:change={handlePublicWindowChange} style="max-width: 140px;">
          {#each publicWindowOptions as option}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
      <HeatMap
        points={publicHeatPoints}
        height={520}
        emptyMessage={publicHeatmapMessage}
        pulseKey={publicPulseKey}
        mimosaLocation={mimosaLocation}
        attackOrigins={publicAttackOrigins}
        attackKey={publicAttackKey}
      />
      <div style="margin-top: 8px; color: var(--muted); font-size: 12px;">
        {publicHeatmapMessage}
      </div>
    </div>
    <div class="surface panel">
      <div class="badge">Geo</div>
      <h3 class="card-title" style="margin-top: 12px;">Ranking por pais</h3>
      <div class="list" style="margin-top: 12px;">
        {#if publicCountries.length === 0}
          <div class="list-item">Sin datos geo.</div>
        {:else}
          {#each publicCountries as entry}
            <div class="list-item">
              <span>{countryFlag(entry.country_code)} {entry.country}</span>
              <strong>{entry.offenses}</strong>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </section>

  <section class="section split">
    <div class="surface panel">
      <div class="badge">Actividad</div>
      <div class="card-title-row">
        <h3 class="card-title">Actividad en vivo</h3>
        <div class="card-subtitle">
          {#if publicLastAt}
            Actualizado: {formatTime(publicLastAt)}
          {/if}
        </div>
      </div>
      <div class="list" style="margin-top: 12px;">
        {#if publicFeed.length === 0}
          <div class="list-item">Sin actividad reciente.</div>
        {:else}
          {#each publicFeed as item}
            <div class="list-item live-row">
              <span class="live-left">
                {countryFlag(item.country_code)}
                <a class="ip-link" href={ipHref(item.source_ip)}>{item.source_ip}</a>
                <span class="live-plugin">· {item.plugin || 'ofensa'}</span>
              </span>
              <span
                class="live-reason"
                title={item.description_clean || item.description}
              >
                {item.description_clean || item.description}
              </span>
              <strong class="live-time">{formatTime(item.created_at)}</strong>
            </div>
          {/each}
        {/if}
      </div>
    </div>
    <div class="surface panel">
      <div class="badge">Tipos</div>
      <div class="card-title-row">
        <h3 class="card-title">Tipo de ofensa</h3>
        <select value={publicWindow} on:change={handlePublicWindowChange} style="max-width: 140px;">
          {#each publicWindowOptions as option}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
      <ChartCanvas
        labels={publicTypeLabels}
        data={publicTypeValues}
        label="Tipos"
        type="doughnut"
        showLegend={true}
      />
      <div class="list" style="margin-top: 12px;">
        {#if publicTypes.length === 0}
          <div class="list-item">Sin datos de tipos.</div>
        {:else}
          {#each publicTypes as entry}
            <div class="list-item">
              <span>{entry.type}</span>
              <strong>{entry.count}</strong>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </section>
{:else}
<div class="dashboard-tabs">
  {#each tabs as tab}
    <button
      class="dashboard-tab {activeTab === tab.value ? 'active' : ''}"
      on:click={() => setTab(tab.value)}
    >
      {tab.label}
    </button>
  {/each}
</div>

{#if error}
  <div class="surface panel-sm" style="border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

{#if activeTab === 'overview'}
  {#if !error}
    <div class="card-grid">
      <StatCard
        title="Bloqueos activos"
        value={stats?.blocks.current ?? '-'}
        subtitle="Activos ahora"
        trend="neutral"
      />
      <StatCard
        title="Actividad 24h"
        value={
          stats
            ? `${stats.offenses.last_24h} / ${stats.blocks.last_24h}`
            : '-'
        }
        subtitle="Ofensas / Bloqueos"
        trend="up"
      />
      <StatCard
        title="Actividad 7d"
        value={
          stats
            ? `${stats.offenses.last_7d} / ${stats.blocks.last_7d}`
            : '-'
        }
        subtitle="Ofensas / Bloqueos"
        trend="neutral"
      />
    </div>
  {/if}

  <section class="section split">
    <div class="surface panel">
      <div class="badge">Tendencias</div>
      <div class="card-title-row">
        <h3 class="card-title">Ofensas</h3>
        <select bind:value={offenseWindow} on:change={handleOffenseWindowChange} style="max-width: 120px;">
          {#each windowOptions as option}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
      <ChartCanvas labels={offenseLabels} data={offenseValues} label="Ofensas" color="#38bdf8" />
    </div>
    <div class="surface panel">
      <div class="badge">Tendencias</div>
      <div class="card-title-row">
        <h3 class="card-title">Bloqueos</h3>
        <select bind:value={blockWindow} on:change={handleBlockWindowChange} style="max-width: 120px;">
          {#each windowOptions as option}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
      <ChartCanvas labels={blockLabels} data={blockValues} label="Bloqueos" color="#2dd4bf" />
    </div>
  </section>

  <section class="section split">
    <div class="surface panel">
      <div class="badge">Ratio</div>
      <h3 class="card-title" style="margin-top: 12px;">Ofensas por bloqueo (24h)</h3>
      <ChartCanvas
        labels={ratioLabels}
        data={ratioValues}
        label="Ofensas por bloqueo"
        color="#fbbf24"
      />
    </div>
    <div class="surface panel">
      <div class="badge">Live</div>
      <div class="card-title-row">
        <h3 class="card-title">Feed en vivo</h3>
        <span class="tag">{wsLabel()}</span>
      </div>
      <div class="toolbar" style="margin-top: 8px;">
        <select bind:value={liveFilter} style="max-width: 200px;">
          <option value="">Todas</option>
          <option value="mimosanpm">MimosaNPM</option>
          <option value="proxytrap">ProxyTrap</option>
          <option value="portdetector">Port Detector</option>
          <option value="blocks">Bloqueos</option>
        </select>
        <div class="card-subtitle">
          {#if wsStatus === 'auth_required'}
            Inicia sesion para ver eventos.
          {:else if lastLiveAt}
            Ultima actualizacion: {formatTime(lastLiveAt)}
          {/if}
        </div>
      </div>
      <div class="list" style="margin-top: 12px;">
        {#if liveFeed.length === 0}
          <div class="list-item">Esperando eventos...</div>
        {:else}
          {#each liveFeed as item}
            <div class="list-item">
              <div>
                <div style="font-weight: 600;">
                  {item.kind === 'offense' ? 'Ofensa' : 'Bloqueo'} -
                  <a class="ip-link" href={ipHref(item.ip)}>{item.ip}</a>
                </div>
                <div style="color: var(--muted); font-size: 12px;">{item.detail}</div>
              </div>
              <strong>{formatTime(item.at)}</strong>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </section>
{/if}

{#if activeTab === 'map'}
  <section class="section split public-geo">
    <div class="surface panel">
      <div class="badge">Heatmap</div>
      <div class="card-title-row">
        <h3 class="card-title">Actividad global</h3>
        <select value={heatmapWindow} on:change={handleHeatmapChange} style="max-width: 140px;">
          {#each heatmapOptions as option}
            <option value={option.value}>{option.label}</option>
          {/each}
        </select>
      </div>
      <HeatMap
        points={heatPoints}
        height={520}
        emptyMessage={heatmapMessage}
        mimosaLocation={mimosaLocation}
        attackOrigins={mapAttackOrigins}
        attackKey={mapAttackKey}
      />
      <div style="margin-top: 8px; color: var(--muted); font-size: 12px;">
        {heatmapMessage}
      </div>
    </div>
    <div class="surface panel">
      <div class="badge">Geo</div>
      <h3 class="card-title" style="margin-top: 12px;">Ranking por pais</h3>
      <div class="list" style="margin-top: 12px;">
        {#if countryEntries.length === 0}
          <div class="list-item">Sin datos geo.</div>
        {:else}
          {#each countryEntries as entry}
            <div class="list-item">
              <span>{countryFlag(entry.country_code)} {entry.country}</span>
              <strong>{entry.blocks}</strong>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  </section>

  <section class="section split">
    <div class="surface panel">
      <div class="badge">Ultimas ofensas</div>
      <h3 class="card-title" style="margin-top: 12px;">Actividad reciente</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive table-prominent table-fixed">
          <thead>
            <tr>
              <th>IP</th>
              <th>Motivo</th>
              {#if showOffenseCounts}
                <th class="cell-right">1h</th>
                <th class="cell-right">Total</th>
                <th class="cell-right">Bloqueos</th>
              {/if}
            </tr>
          </thead>
          <tbody>
            {#if latestOffenses.length === 0}
              <tr><td colspan={showOffenseCounts ? 5 : 2}>Sin datos recientes.</td></tr>
            {:else}
              {#each latestOffenses as offense}
                {@const reasonText = offense.reason_text || offense.description_clean || offense.description}
                {@const pluginLabel = offense.reason_plugin || offense.plugin || 'ofensa'}
                {@const counts = offense.reason_counts}
                <tr>
                  <td data-label="IP">
                    <a class="ip-link" href={ipHref(offense.source_ip)}>{offense.source_ip}</a>
                  </td>
                  <td data-label="Motivo" class="cell-truncate" title={reasonText}>
                    {reasonText}
                    <div class="cell-muted">
                      {pluginLabel}
                    </div>
                  </td>
                  {#if showOffenseCounts}
                    <td class="cell-right" data-label="1h">{counts?.offenses_1h ?? '-'}</td>
                    <td class="cell-right" data-label="Total">{counts?.offenses_total ?? '-'}</td>
                    <td class="cell-right" data-label="Bloqueos">{counts?.blocks_total ?? '-'}</td>
                  {/if}
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
    <div class="surface panel">
      <div class="badge">Ultimos bloqueos</div>
      <h3 class="card-title" style="margin-top: 12px;">Bloqueos recientes</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive table-prominent table-fixed">
          <thead>
            <tr>
              <th>IP</th>
              <th>Motivo</th>
              <th class="cell-right">Bloqueos</th>
            </tr>
          </thead>
          <tbody>
            {#if latestBlocks.length === 0}
              <tr><td colspan="3">Sin bloqueos recientes.</td></tr>
            {:else}
              {#each latestBlocks as block}
                {@const reasonText = block.reason_text || block.reason || '-'}
                <tr>
                  <td data-label="IP">
                    <a class="ip-link" href={ipHref(block.ip)}>{block.ip}</a>
                  </td>
                  <td data-label="Motivo" class="cell-truncate" title={block.reason}>
                    {reasonText}
                  </td>
                  <td class="cell-right" data-label="Bloqueos">
                    {block.reason_counts?.blocks_total ?? '-'}
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  </section>
{/if}

{#if activeTab === 'insights'}
  {#if insightsError}
    <div class="surface panel-sm" style="border-color: rgba(248, 113, 113, 0.5);">
      <strong>Error</strong>
      <div style="color: var(--muted); margin-top: 4px;">{insightsError}</div>
    </div>
  {/if}
  <section class="section" style="grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));">
    <div class="surface panel">
      <div class="card-head">
        <div class="badge">Riesgo</div>
        <button class="ghost" on:click={loadInsights}>Refrescar</button>
      </div>
      <h3 class="card-title">Top IPs</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th class="cell-nowrap">IP</th>
              <th class="cell-right">Score</th>
              <th class="cell-right">Ofensas</th>
              <th class="cell-right">Bloqueos</th>
            </tr>
          </thead>
          <tbody>
            {#if topIps.length === 0}
              <tr><td colspan="4">Sin datos.</td></tr>
            {:else}
              {#each topIps as item}
                <tr>
                  <td data-label="IP">
                    <a class="ip-link" href={ipHref(item.ip)}>{item.ip}</a>
                  </td>
                  <td class="cell-right" data-label="Score">{item.score}</td>
                  <td class="cell-right" data-label="Ofensas">{item.offenses}</td>
                  <td class="cell-right" data-label="Bloqueos">{item.blocks}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
    <div class="surface panel">
      <div class="card-head">
        <div class="badge">Expiran</div>
        <button class="ghost" on:click={loadInsights}>Refrescar</button>
      </div>
      <h3 class="card-title">Bloqueos por expirar</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th>IP</th>
              <th class="cell-right">Min</th>
              <th class="cell-right">Bloqueos</th>
              <th>Motivo</th>
              <th>Plugin</th>
            </tr>
          </thead>
          <tbody>
            {#if expiringBlocks.length === 0}
              <tr><td colspan="5">Sin datos.</td></tr>
            {:else}
              {#each expiringBlocks as item}
                <tr>
                  <td data-label="IP">
                    <a class="ip-link" href={ipHref(item.ip)}>{item.ip}</a>
                  </td>
                  <td class="cell-right" data-label="Min">{item.minutes_left}</td>
                  <td class="cell-right" data-label="Bloqueos">
                    {item.reason_counts?.blocks_total ?? '-'}
                  </td>
                  <td class="cell-truncate" title={item.reason || '-'} data-label="Motivo">
                    {item.reason_text || item.reason || '-'}
                  </td>
                  <td data-label="Plugin">{item.reason_plugin || '-'}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
    <div class="surface panel">
      <div class="card-head">
        <div class="badge">Eficacia</div>
        <button class="ghost" on:click={loadInsights}>Refrescar</button>
      </div>
      <h3 class="card-title">Motivos frecuentes</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th>Motivo</th>
              <th>Plugin</th>
              <th class="cell-right">Bloqueos</th>
            </tr>
          </thead>
          <tbody>
            {#if blockReasons.length === 0}
              <tr><td colspan="3">Sin datos.</td></tr>
            {:else}
              {#each blockReasons as item}
                <tr>
                  <td data-label="Motivo">{item.reason_text || item.reason}</td>
                  <td data-label="Plugin">{item.reason_plugin || '-'}</td>
                  <td class="cell-right" data-label="Bloqueos">{item.count}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  </section>
{/if}

{#if activeTab === 'health'}
  <section class="section split">
    <div class="surface panel">
      <div class="card-head">
        <div class="badge">Health</div>
        <button class="ghost" on:click={loadInsights}>Refrescar</button>
      </div>
      <h3 class="card-title">Firewalls</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Estado</th>
              <th class="cell-right">Latencia</th>
            </tr>
          </thead>
          <tbody>
            {#if firewallsHealth.length === 0}
              <tr><td colspan="3">Sin firewalls.</td></tr>
            {:else}
              {#each firewallsHealth as fw}
                <tr>
                  <td data-label="Nombre">{fw.name} ({fw.type})</td>
                  <td data-label="Estado">
                    <span class="tag" style="color: {fw.available ? 'var(--success)' : 'var(--danger)'};">
                      {fw.available ? 'Online' : 'Offline'}
                    </span>
                  </td>
                  <td class="cell-right" data-label="Latencia">
                    {fw.latency_ms ?? '-'}{fw.latency_ms ? ' ms' : ''}
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
    <div class="surface panel">
      <div class="card-head">
        <div class="badge">Health</div>
        <button class="ghost" on:click={loadInsights}>Refrescar</button>
      </div>
      <h3 class="card-title">Plugins</h3>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th>Plugin</th>
              <th>Estado</th>
              <th class="cell-right">Eventos 24h</th>
              <th class="cell-nowrap">Ultimo</th>
            </tr>
          </thead>
          <tbody>
            {#if pluginsHealth.length === 0}
              <tr><td colspan="4">Sin plugins.</td></tr>
            {:else}
              {#each pluginsHealth as plugin}
                <tr>
                  <td data-label="Plugin">{plugin.name}</td>
                  <td data-label="Estado">
                    <span class="tag" style="color: {plugin.enabled ? 'var(--success)' : 'var(--warning)'};">
                      {plugin.enabled ? 'Activo' : 'Inactivo'}
                    </span>
                  </td>
                  <td class="cell-right" data-label="Eventos 24h">{plugin.last_24h}</td>
                  <td class="cell-nowrap" data-label="Ultimo">{formatDate(plugin.last_event_at)}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  </section>
{/if}

{#if activeTab === 'plugins'}
  <section class="section" style="grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));">
    <div class="surface panel">
      <div class="badge">Plugins</div>
      <h3 class="card-title" style="margin-top: 12px;">ProxyTrap</h3>
      <ChartCanvas
        labels={proxyLabels}
        data={proxyValues}
        label="Hits"
        color="#f87171"
        type="bar"
      />
      <div class="list" style="margin-top: 12px;">
        {#if proxyStats?.top_domains?.length}
          {#each proxyStats.top_domains.slice(0, 5) as entry}
            <div class="list-item">
              <span>{entry.domain}</span>
              <strong>{entry.hits}</strong>
            </div>
          {/each}
        {:else}
          <div class="list-item">Sin datos de ProxyTrap.</div>
        {/if}
      </div>
    </div>
    <div class="surface panel">
      <div class="badge">Plugins</div>
      <h3 class="card-title" style="margin-top: 12px;">PortDetector</h3>
      <ChartCanvas
        labels={portLabels}
        data={portValues}
        label="Hits"
        color="#38bdf8"
        type="bar"
      />
      <div class="list" style="margin-top: 12px;">
        {#if portStats?.top_ports?.length}
          {#each portStats.top_ports as entry}
            <div class="list-item">
              <span>{entry.protocol.toUpperCase()} {entry.port}</span>
              <strong>{entry.hits}</strong>
            </div>
          {/each}
        {:else}
          <div class="list-item">Sin datos de PortDetector.</div>
        {/if}
      </div>
    </div>
    <div class="surface panel">
      <div class="badge">Plugins</div>
      <h3 class="card-title" style="margin-top: 12px;">MimosaNPM</h3>
      {#if mimosanpmStats}
        <div style="margin-top: 10px; color: var(--muted); font-size: 12px;">
          {mimosanpmStats.total} eventos (muestra {mimosanpmStats.sample})
        </div>
        <div class="mini-grid" style="margin-top: 12px;">
          <div>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 6px;">Hosts</div>
            <ChartCanvas
              labels={npmDomainLabels}
              data={npmDomainValues}
              label="Hosts"
              type="doughnut"
            />
          </div>
          <div>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 6px;">Paths</div>
            <ChartCanvas
              labels={npmPathLabels}
              data={npmPathValues}
              label="Paths"
              type="doughnut"
            />
          </div>
          <div>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 6px;">Status</div>
            <ChartCanvas
              labels={npmStatusLabels}
              data={npmStatusValues}
              label="Status"
              type="doughnut"
            />
          </div>
        </div>
      {:else}
        <div style="margin-top: 10px; color: var(--muted); font-size: 12px;">
          Sin datos recientes.
        </div>
      {/if}
    </div>
  </section>
{/if}
{/if}
