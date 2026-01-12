<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import 'leaflet/dist/leaflet.css';

  export let location: { lat: number; lon: number } | null = null;
  export let height = 220;

  let mapEl: HTMLDivElement | null = null;
  let map: any = null;
  let marker: any = null;
  let L: any = null;
  let initialized = false;

  const updateMarker = () => {
    if (!map || !L) {
      return;
    }
    if (!location) {
      if (marker) {
        marker.remove();
        marker = null;
      }
      return;
    }
    const latlng: [number, number] = [location.lat, location.lon];
    if (!marker) {
      marker = L.circleMarker(latlng, {
        radius: 6,
        color: '#facc15',
        fillColor: '#fde047',
        fillOpacity: 0.9,
        weight: 2,
        className: 'mimosa-marker'
      }).addTo(map);
      return;
    }
    marker.setLatLng(latlng);
  };

  const buildMap = async () => {
    if (!mapEl) {
      return;
    }
    const leaflet = await import('leaflet');
    L = leaflet.default ?? leaflet;

    map = L.map(mapEl, {
      zoomControl: true,
      attributionControl: false
    });

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18
    }).addTo(map);

    if (location) {
      map.setView([location.lat, location.lon], 4);
    } else {
      map.setView([20, 0], 2);
    }

    map.on('click', (event: { latlng: { lat: number; lng: number } }) => {
      location = {
        lat: Number(event.latlng.lat.toFixed(6)),
        lon: Number(event.latlng.lng.toFixed(6))
      };
      updateMarker();
      if (!initialized) {
        map.setView([location.lat, location.lon], 4);
        initialized = true;
      }
    });

    updateMarker();
  };

  $: if (map) {
    updateMarker();
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

<div class="location-map" style={`height: ${height}px;`}>
  <div class="map-container" bind:this={mapEl}></div>
</div>
