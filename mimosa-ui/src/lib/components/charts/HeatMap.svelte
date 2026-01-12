<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import 'leaflet/dist/leaflet.css';

  export type HeatPoint = {
    lat: number;
    lon: number;
    count: number;
  };

  export let points: HeatPoint[] = [];
  export let mimosaLocation: { lat: number; lon: number } | null = null;
  export let attackOrigins: { lat: number; lon: number }[] = [];
  export let height = 240;
  export let emptyMessage = 'Sin datos de geolocalizacion.';
  export let pulseKey = 0;
  export let attackKey = 0;

  let mapEl: HTMLDivElement | null = null;
  let map: any = null;
  let layer: any = null;
  let attackLayer: any = null;
  let L: any = null;
  let lastPulseKey = 0;
  let mimosaMarker: any = null;

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

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18
    }).addTo(map);

    layer = L.layerGroup().addTo(map);
    attackLayer = L.layerGroup().addTo(map);
    updatePoints();
    updateMimosaMarker();
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
      }, 1200);
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
</div>
