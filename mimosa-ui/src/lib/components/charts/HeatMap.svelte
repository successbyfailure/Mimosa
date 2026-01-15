<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import 'leaflet/dist/leaflet.css';

  export type HeatPoint = {
    lat: number;
    lon: number;
    count: number;
  };

  export type CountryData = {
    country: string;
    country_code?: string;
    blocks?: number;
    offenses?: number;
  };

  export let points: HeatPoint[] = [];
  export let mimosaLocation: { lat: number; lon: number } | null = null;
  export let attackOrigins: { lat: number; lon: number }[] = [];
  export let countryData: CountryData[] = [];
  export let height = 240;
  export let emptyMessage = 'Sin datos de geolocalizacion.';
  export let pulseKey = 0;
  export let attackKey = 0;

  let mapEl: HTMLDivElement | null = null;
  let map: any = null;
  let layer: any = null;
  let attackLayer: any = null;
  let countriesLayer: any = null;
  let L: any = null;
  let lastPulseKey = 0;
  let mimosaMarker: any = null;
  let countriesGeoJson: any = null;
  const attackDurationMs = 5000;

  const normalizeCountryName = (value: string): string =>
    value
      .toLowerCase()
      .replace(/['’`]/g, '')
      .replace(/[^a-z0-9\s]/g, ' ')
      .replace(/\bthe\b/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();

  const countryNameAliases: Record<string, string[]> = {
    [normalizeCountryName('United States of America')]: [
      normalizeCountryName('United States'),
      normalizeCountryName('USA'),
      normalizeCountryName('US')
    ],
    [normalizeCountryName('Russian Federation')]: [normalizeCountryName('Russia')],
    [normalizeCountryName('Iran')]: [normalizeCountryName('Iran, Islamic Republic of')],
    [normalizeCountryName('Viet Nam')]: [normalizeCountryName('Vietnam')],
    [normalizeCountryName('Republic of Korea')]: [normalizeCountryName('South Korea')],
    [normalizeCountryName("Democratic People's Republic of Korea")]: [
      normalizeCountryName('North Korea')
    ],
    [normalizeCountryName('United Republic of Tanzania')]: [normalizeCountryName('Tanzania')],
    [normalizeCountryName("Lao People's Democratic Republic")]: [normalizeCountryName('Laos')],
    [normalizeCountryName('Czechia')]: [normalizeCountryName('Czech Republic')],
    [normalizeCountryName('Bolivia')]: [normalizeCountryName('Bolivia (Plurinational State of)')],
    [normalizeCountryName('Venezuela')]: [normalizeCountryName('Venezuela (Bolivarian Republic of)')],
    [normalizeCountryName('Syrian Arab Republic')]: [normalizeCountryName('Syria')],
    [normalizeCountryName('Republic of Moldova')]: [normalizeCountryName('Moldova')],
    [normalizeCountryName('North Macedonia')]: [
      normalizeCountryName('The former Yugoslav Republic of Macedonia')
    ],
    [normalizeCountryName('Democratic Republic of the Congo')]: [
      normalizeCountryName('Congo, The Democratic Republic of the')
    ],
    [normalizeCountryName('Republic of the Congo')]: [normalizeCountryName('Congo')],
    [normalizeCountryName("Cote d'Ivoire")]: [normalizeCountryName("Côte d'Ivoire")]
  };

  const findCountryEntry = (countryName: string): CountryData | null => {
    if (!countryData.length) {
      return null;
    }
    const normalized = normalizeCountryName(countryName);
    let entry = countryData.find(
      (d) => normalizeCountryName(d.country) === normalized
    );
    if (entry) {
      return entry;
    }
    const aliases = countryNameAliases[normalized] || [];
    if (aliases.length) {
      entry = countryData.find((d) => aliases.includes(normalizeCountryName(d.country)));
      if (entry) {
        return entry;
      }
    }
    return null;
  };

  const buildMap = async () => {
    if (!mapEl) {
      return;
    }
    const leaflet = await import('leaflet');
    L = leaflet.default ?? leaflet;

    map = L.map(mapEl, {
      zoomControl: false,
      attributionControl: false
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      maxZoom: 18,
      subdomains: 'abcd'
    }).addTo(map);

    const countriesPane = map.createPane('countries');
    countriesPane.style.zIndex = '200';
    const pointsPane = map.createPane('points');
    pointsPane.style.zIndex = '300';
    const attacksPane = map.createPane('attacks');
    attacksPane.style.zIndex = '400';
    const markersPane = map.createPane('markers');
    markersPane.style.zIndex = '450';

    countriesLayer = L.layerGroup([], { pane: 'countries' }).addTo(map);
    layer = L.layerGroup([], { pane: 'points' }).addTo(map);
    attackLayer = L.layerGroup([], { pane: 'attacks' }).addTo(map);

    await loadCountriesGeoJson();
    updateCountriesLayer();
    updatePoints();
    updateMimosaMarker();
  };

  const loadCountriesGeoJson = async () => {
    try {
      const response = await fetch('/countries.geojson');
      countriesGeoJson = await response.json();
    } catch (error) {
      console.error('Error loading countries GeoJSON:', error);
    }
  };

  const getCountryColor = (countryName: string): string => {
    if (!countryData.length) {
      return '#1e293b'; // Default dark color
    }

    const data = findCountryEntry(countryName);

    if (!data) {
      return '#1e293b'; // No data - dark gray
    }

    const count = data.blocks ?? data.offenses ?? 0;

    // Calculate max count for normalization
    const maxCount = Math.max(...countryData.map((d) => d.blocks ?? d.offenses ?? 0));

    if (maxCount === 0) {
      return '#1e293b';
    }

    // Calculate percentage
    const percentage = (count / maxCount) * 100;

    // Color scale based on danger level
    if (percentage >= 70) {
      return '#f87171'; // High danger - red
    } else if (percentage >= 40) {
      return '#fbbf24'; // Medium danger - amber
    } else if (percentage >= 10) {
      return '#fb923c'; // Low-medium danger - orange
    } else if (count > 0) {
      return '#4ade80'; // Low danger - green
    } else {
      return '#1e293b'; // No data
    }
  };

  const updateCountriesLayer = () => {
    if (!map || !L || !countriesLayer || !countriesGeoJson) {
      return;
    }

    countriesLayer.clearLayers();

    L.geoJSON(countriesGeoJson, {
      pane: 'countries',
      style: (feature: any) => {
        const countryName = feature.properties.name;
        return {
          fillColor: getCountryColor(countryName),
          fillOpacity: 0.35,
          color: '#1f2937',
          weight: 0.8,
          opacity: 0.45
        };
      },
      onEachFeature: (feature: any, layer: any) => {
        const countryName = feature.properties.name;
        const data = findCountryEntry(countryName);

        if (data) {
          const count = data.blocks ?? data.offenses ?? 0;
          layer.bindTooltip(
            `<strong>${countryName}</strong><br/>${count} ${data.blocks !== undefined ? 'bloques' : 'ofensas'}`,
            { sticky: true }
          );
        }
      }
    }).addTo(countriesLayer);
  };

  const updatePoints = () => {
    if (!map || !layer || !L) {
      return;
    }
    layer.clearLayers();
    if (!points.length) {
      map.setView([20, 0], 2);
      lastPulseKey = pulseKey;
      return;
    }
    const bounds: [number, number][] = [];
    for (const point of points) {
      const radius = Math.max(2, Math.min(30, 6 + Math.log(point.count + 1) * 5) * 0.25);
      L.circleMarker([point.lat, point.lon], {
        pane: 'points',
        radius,
        color: '#ef4444',
        fillColor: '#f87171',
        fillOpacity: 0.45,
        weight: 1,
        className: 'heat-marker'
      }).addTo(layer);
      bounds.push([point.lat, point.lon]);
    }
    map.fitBounds(bounds, { padding: [20, 20], maxZoom: 5 });
    lastPulseKey = pulseKey;
  };

  const updateMimosaMarker = () => {
    if (!map || !L) {
      return;
    }
    if (!mimosaLocation) {
      if (mimosaMarker) {
        mimosaMarker.remove();
        mimosaMarker = null;
      }
      return;
    }
    const latlng: [number, number] = [mimosaLocation.lat, mimosaLocation.lon];
    if (!mimosaMarker) {
      mimosaMarker = L.circleMarker(latlng, {
        pane: 'markers',
        radius: 6,
        color: '#facc15',
        fillColor: '#fde047',
        fillOpacity: 0.9,
        weight: 2,
        className: 'mimosa-marker'
      }).addTo(map);
      return;
    }
    mimosaMarker.setLatLng(latlng);
  };

  const triggerAttackBeams = () => {
    if (!map || !L || !attackLayer) {
      return;
    }
    attackLayer.clearLayers();
    if (!mimosaLocation || !attackOrigins.length) {
      return;
    }
    const animateProjectile = (origin: { lat: number; lon: number }) => {
      if (!mimosaLocation || !L || !attackLayer) {
        return;
      }
      const projectile = L.circleMarker([origin.lat, origin.lon], {
        pane: 'attacks',
        radius: 2.5,
        color: '#e2e8f0',
        fillColor: '#f8fafc',
        fillOpacity: 0.9,
        weight: 1,
        className: 'attack-projectile'
      }).addTo(attackLayer);
      const halo = L.circleMarker([origin.lat, origin.lon], {
        pane: 'attacks',
        radius: 5,
        color: '#cbd5f5',
        fillColor: '#cbd5f5',
        fillOpacity: 0.04,
        weight: 1,
        className: 'attack-projectile-halo'
      }).addTo(attackLayer);
      const start = performance.now();
      const step = (now: number) => {
        if (!attackLayer || !attackLayer.hasLayer(projectile)) {
          return;
        }
        const progress = Math.min((now - start) / attackDurationMs, 1);
        const lat = origin.lat + (mimosaLocation!.lat - origin.lat) * progress;
        const lon = origin.lon + (mimosaLocation!.lon - origin.lon) * progress;
        projectile.setLatLng([lat, lon]);
        halo.setLatLng([lat, lon]);
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          attackLayer.removeLayer(projectile);
          attackLayer.removeLayer(halo);
        }
      };
      requestAnimationFrame(step);
    };

    for (const origin of attackOrigins) {
      const ray = L.polyline(
        [
          [origin.lat, origin.lon],
          [mimosaLocation.lat, mimosaLocation.lon]
        ],
        {
          pane: 'attacks',
          color: '#ef4444',
          weight: 2,
          opacity: 0.9,
          className: 'attack-ray'
        }
      ).addTo(attackLayer);
      window.setTimeout(() => {
        attackLayer.removeLayer(ray);
      }, attackDurationMs);
      L.circleMarker([origin.lat, origin.lon], {
        pane: 'attacks',
        radius: 5,
        color: '#fca5a5',
        fillColor: '#f87171',
        fillOpacity: 0.25,
        weight: 1.2,
        className: 'attack-origin-pulse'
      }).addTo(attackLayer);
      L.circleMarker([mimosaLocation.lat, mimosaLocation.lon], {
        pane: 'attacks',
        radius: 5,
        color: '#38bdf8',
        fillColor: '#0ea5e9',
        fillOpacity: 0.25,
        weight: 1.2,
        className: 'attack-destination-pulse'
      }).addTo(attackLayer);
      animateProjectile(origin);
    }
    const latest = attackOrigins[attackOrigins.length - 1];
    if (latest) {
      const latestRay = L.polyline(
        [
          [latest.lat, latest.lon],
          [mimosaLocation.lat, mimosaLocation.lon]
        ],
        {
          pane: 'attacks',
          color: '#94a3b8',
          weight: 3,
          opacity: 0.8,
          className: 'attack-latest-ray'
        }
      ).addTo(attackLayer);
      latestRay.bringToFront();
      L.circleMarker([latest.lat, latest.lon], {
        pane: 'attacks',
        radius: 9,
        color: '#94a3b8',
        fillColor: '#94a3b8',
        fillOpacity: 0.03,
        weight: 0.8,
        className: 'attack-latest-halo'
      }).addTo(attackLayer);
    }
  };

  $: if (map) {
    pulseKey;
    points;
    updatePoints();
  }

  $: if (map) {
    mimosaLocation;
    updateMimosaMarker();
  }

  $: if (map) {
    attackKey;
    attackOrigins;
    triggerAttackBeams();
  }

  $: if (map && countriesGeoJson) {
    countryData;
    updateCountriesLayer();
  }

  onMount(() => {
    buildMap();
  });

  onDestroy(() => {
    if (map) {
      map.remove();
    }
  });
</script>

<div class="map-wrapper" style={`height: ${height}px;`}>
  <div class="map-container" bind:this={mapEl}></div>
  {#if points.length === 0}
    <div class="map-empty">{emptyMessage}</div>
  {/if}
  {#if countryData.length > 0}
    <div class="map-legend">
      <div class="legend-title">Nivel de Amenaza</div>
      <div class="legend-item">
        <span class="legend-color" style="background-color: #f87171;"></span>
        <span class="legend-label">Alto</span>
      </div>
      <div class="legend-item">
        <span class="legend-color" style="background-color: #fbbf24;"></span>
        <span class="legend-label">Medio</span>
      </div>
      <div class="legend-item">
        <span class="legend-color" style="background-color: #fb923c;"></span>
        <span class="legend-label">Bajo-Medio</span>
      </div>
      <div class="legend-item">
        <span class="legend-color" style="background-color: #4ade80;"></span>
        <span class="legend-label">Bajo</span>
      </div>
    </div>
  {/if}
</div>

<style>
  .map-legend {
    position: absolute;
    bottom: 10px;
    right: 10px;
    background: rgba(15, 23, 42, 0.9);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 8px 12px;
    font-size: 12px;
    z-index: 1000;
    backdrop-filter: blur(4px);
  }

  .legend-title {
    font-weight: 600;
    margin-bottom: 6px;
    color: var(--text);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .legend-item {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 4px 0;
  }

  .legend-color {
    width: 16px;
    height: 12px;
    border-radius: 2px;
    opacity: 0.8;
  }

  .legend-label {
    color: var(--text-muted);
    font-size: 11px;
  }
</style>
