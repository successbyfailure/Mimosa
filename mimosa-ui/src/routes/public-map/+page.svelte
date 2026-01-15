<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import HeatMap from '$lib/components/charts/HeatMap.svelte';

  type HeatPoint = { lat: number; lon: number; count: number };
  type CountryEntry = { country: string; country_code?: string; offenses?: number };
  type PublicOffense = { lat: number | null; lon: number | null; created_at: string };

  let points: HeatPoint[] = [];
  let countries: CountryEntry[] = [];
  let mimosaLocation: { lat: number; lon: number } | null = null;
  let attackOrigins: { lat: number; lon: number }[] = [];
  let attackKey = 0;
  let pulseKey = 0;
  let heatmapMessage = 'Cargando datos...';
  let latestEventMs: number | null = null;

  let mapWindow = '24h';
  const mapWindowOptions = [
    { value: '24h', label: '24h' },
    { value: '7d', label: '7d' },
    { value: '30d', label: '30d' },
    { value: 'total', label: 'Total' }
  ];

  let feedTimer: ReturnType<typeof setInterval> | null = null;
  let mapTimer: ReturnType<typeof setInterval> | null = null;

  const loadLocation = async () => {
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

  const loadMap = async () => {
    heatmapMessage = 'Cargando datos...';
    try {
      const [heatResponse, countryResponse] = await Promise.all([
        fetch(`/api/public/heatmap?window=${mapWindow}&limit=300`),
        fetch(`/api/public/offenses_by_country?window=${mapWindow}&limit=200`)
      ]);
      if (heatResponse.ok) {
        const payload = (await heatResponse.json()) as {
          points: HeatPoint[];
          points_count?: number;
        };
        points = payload.points || [];
        pulseKey += 1;
        if (!points.length) {
          heatmapMessage = 'Sin datos de geolocalizacion.';
        } else if (payload.points_count) {
          heatmapMessage = `Puntos: ${payload.points_count}`;
        } else {
          heatmapMessage = '';
        }
      } else {
        points = [];
        heatmapMessage = 'No se pudo cargar el mapa.';
      }
      if (countryResponse.ok) {
        const payload = (await countryResponse.json()) as { countries: CountryEntry[] };
        countries = payload.countries || [];
      }
    } catch (err) {
      points = [];
      heatmapMessage = 'No se pudo cargar el mapa.';
    }
  };

  const loadFeed = async () => {
    try {
      const response = await fetch('/api/public/feed?limit=10');
      if (!response.ok) {
        return;
      }
      const payload = (await response.json()) as PublicOffense[];
      const latest = payload[0]?.created_at;
      const latestMs = latest ? new Date(latest).getTime() : null;
      if (latestMs && latestMs !== latestEventMs) {
        const origins: { lat: number; lon: number }[] = [];
        for (const item of payload) {
          const itemMs = new Date(item.created_at).getTime();
          if (latestEventMs && itemMs <= latestEventMs) {
            continue;
          }
          if (item.lat == null || item.lon == null) {
            continue;
          }
          origins.push({ lat: item.lat, lon: item.lon });
        }
        if (origins.length) {
          attackOrigins = origins;
          attackKey += 1;
        }
        latestEventMs = latestMs;
      }
    } catch (err) {
      // ignore
    }
  };

  const handleWindowChange = (event: Event) => {
    const target = event.target as HTMLSelectElement;
    mapWindow = target.value;
    loadMap();
  };

  onMount(() => {
    loadLocation();
    loadMap();
    loadFeed();
    feedTimer = setInterval(loadFeed, 5000);
    mapTimer = setInterval(loadMap, 60000);
  });

  onDestroy(() => {
    if (feedTimer) {
      clearInterval(feedTimer);
    }
    if (mapTimer) {
      clearInterval(mapTimer);
    }
  });
</script>

<section class="section" style="padding-top: 16px;">
  <div class="surface panel" style="margin: 0; padding: 16px;">
    <div class="card-title-row">
      <div>
        <div class="badge">Heatmap</div>
        <h3 class="card-title" style="margin-top: 10px;">Actividad global</h3>
      </div>
      <select value={mapWindow} on:change={handleWindowChange} style="max-width: 140px;">
        {#each mapWindowOptions as option}
          <option value={option.value}>{option.label}</option>
        {/each}
      </select>
    </div>
    <HeatMap
      points={points}
      height={520}
      emptyMessage={heatmapMessage}
      pulseKey={pulseKey}
      mimosaLocation={mimosaLocation}
      attackOrigins={attackOrigins}
      attackKey={attackKey}
      countryData={countries}
    />
    <div style="margin-top: 8px; color: var(--muted); font-size: 12px;">
      {heatmapMessage}
    </div>
  </div>
</section>
