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

    countriesLayer = L.layerGroup().addTo(map);
    layer = L.layerGroup().addTo(map);
    attackLayer = L.layerGroup().addTo(map);

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

    const data = countryData.find(
      (d) => d.country.toLowerCase() === countryName.toLowerCase()
    );

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
      style: (feature: any) => {
        const countryName = feature.properties.name;
        return {
          fillColor: getCountryColor(countryName),
          fillOpacity: 0.6,
          color: '#334155',
          weight: 1,
          opacity: 0.5
        };
      },
      onEachFeature: (feature: any, layer: any) => {
        const countryName = feature.properties.name;
        const data = countryData.find(
          (d) => d.country.toLowerCase() === countryName.toLowerCase()
        );

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
    const shouldPulse = pulseKey !== lastPulseKey;
    const bounds: [number, number][] = [];
    for (const point of points) {
      const radius = Math.max(2, Math.min(30, 6 + Math.log(point.count + 1) * 5) * 0.25);
      L.circleMarker([point.lat, point.lon], {
        radius,
        color: '#ef4444',
        fillColor: '#f87171',
        fillOpacity: 0.45,
        weight: 1,
        className: shouldPulse ? 'heat-marker heat-pulse' : 'heat-marker'
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
    for (const origin of attackOrigins) {
      const ray = L.polyline(
        [
          [origin.lat, origin.lon],
          [mimosaLocation.lat, mimosaLocation.lon]
        ],
        {
          color: '#ef4444',
          weight: 2,
          opacity: 0.9,
          className: 'attack-ray'
        }
      ).addTo(attackLayer);
      window.setTimeout(() => {
        attackLayer.removeLayer(ray);
      }, 5000);
    }
    const latest = attackOrigins[attackOrigins.length - 1];
    if (latest) {
      const latestRay = L.polyline(
        [
          [latest.lat, latest.lon],
          [mimosaLocation.lat, mimosaLocation.lon]
        ],
        {
          color: '#94a3b8',
          weight: 3,
          opacity: 0.8,
          className: 'attack-latest-ray'
        }
      ).addTo(attackLayer);
      latestRay.bringToFront();
      L.circleMarker([latest.lat, latest.lon], {
        radius: 7,
        color: '#a855f7',
        fillColor: '#c084fc',
        fillOpacity: 0.7,
        weight: 2,
        className: 'attack-latest'
      }).addTo(attackLayer);
      L.circleMarker([latest.lat, latest.lon], {
        radius: 12,
        color: '#cbd5f5',
        fillColor: '#cbd5f5',
        fillOpacity: 0.08,
        weight: 1,
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
