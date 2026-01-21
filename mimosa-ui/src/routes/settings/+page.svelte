<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import LocationPicker from '$lib/components/maps/LocationPicker.svelte';
  import TelegramBotSettings from '$lib/components/settings/TelegramBotSettings.svelte';
  import FirewallAdminSettings from '$lib/components/settings/FirewallAdminSettings.svelte';
  import HomeAssistantSettings from '$lib/components/settings/HomeAssistantSettings.svelte';
  import DatabaseSettings from '$lib/components/settings/DatabaseSettings.svelte';

  type BlockingSettings = {
    default_duration_minutes: number;
    sync_interval_seconds: number;
  };

  let settings: BlockingSettings | null = null;
  let loading = false;
  let error: string | null = null;
  let message: string | null = null;
  let saving = false;
  let resetMessage: string | null = null;
  let resetError: string | null = null;
  let resetting = false;
  let location: { lat: number; lon: number } | null = null;
  let locationMessage: string | null = null;
  let locationError: string | null = null;
  let savingLocation = false;

  type SettingsTab =
    | 'blocking'
    | 'location'
    | 'stats'
    | 'database'
    | 'telegram'
    | 'firewall'
    | 'homeassistant';
  const tabs: { value: SettingsTab; label: string }[] = [
    { value: 'blocking', label: 'Bloqueo' },
    { value: 'location', label: 'Ubicacion' },
    { value: 'stats', label: 'Estadisticas' },
    { value: 'database', label: 'Database' },
    { value: 'telegram', label: 'Telegram' },
    { value: 'firewall', label: 'Firewall' },
    { value: 'homeassistant', label: 'Home Assistant' }
  ];
  let activeTab: SettingsTab = 'blocking';

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

  const loadSettings = async () => {
    loading = true;
    error = null;
    try {
      settings = await requestJson<BlockingSettings>('/api/settings/blocking');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const saveSettings = async () => {
    if (!settings) {
      return;
    }
    saving = true;
    error = null;
    message = null;
    try {
      const payload = {
        default_duration_minutes: Number(settings.default_duration_minutes) || 0,
        sync_interval_seconds: Number(settings.sync_interval_seconds) || 0
      };
      settings = await requestJson<BlockingSettings>('/api/settings/blocking', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      message = 'Configuracion guardada';
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo guardar';
    } finally {
      saving = false;
    }
  };

  const resetStats = async () => {
    if (!confirm('Seguro que quieres reiniciar las estadisticas?')) {
      return;
    }
    resetting = true;
    resetMessage = null;
    resetError = null;
    try {
      await requestJson('/api/stats/reset', { method: 'POST' });
      resetMessage = 'Estadisticas reiniciadas';
    } catch (err) {
      resetError = err instanceof Error ? err.message : 'No se pudo reiniciar';
    } finally {
      resetting = false;
    }
  };

  const loadLocation = async () => {
    locationError = null;
    try {
      const payload = await requestJson<{ lat: number | null; lon: number | null }>(
        '/api/settings/location'
      );
      if (payload.lat == null || payload.lon == null) {
        location = null;
        return;
      }
      location = { lat: payload.lat, lon: payload.lon };
    } catch (err) {
      locationError = err instanceof Error ? err.message : 'No se pudo cargar ubicacion';
    }
  };

  const saveLocation = async () => {
    if (!location) {
      locationError = 'Selecciona la ubicacion en el mapa.';
      return;
    }
    savingLocation = true;
    locationMessage = null;
    locationError = null;
    try {
      const payload = { lat: Number(location.lat), lon: Number(location.lon) };
      location = await requestJson<{ lat: number; lon: number }>('/api/settings/location', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      locationMessage = 'Ubicacion guardada';
    } catch (err) {
      locationError = err instanceof Error ? err.message : 'No se pudo guardar ubicacion';
    } finally {
      savingLocation = false;
    }
  };

  onMount(() => {
    loadSettings();
    loadLocation();
  });

  const isSettingsTab = (value: string | null): value is SettingsTab => {
    return value === 'blocking' ||
      value === 'location' ||
      value === 'stats' ||
      value === 'database' ||
      value === 'telegram' ||
      value === 'firewall' ||
      value === 'homeassistant';
  };

  const setTab = (tab: SettingsTab) => {
    activeTab = tab;
    const next = new URL($page.url);
    next.searchParams.set('tab', tab);
    goto(`${next.pathname}?${next.searchParams.toString()}`, { replaceState: true });
  };

  $: if ($page.url.searchParams) {
    const param = $page.url.searchParams.get('tab');
    if (isSettingsTab(param) && param !== activeTab) {
      activeTab = param;
    }
  }
</script>

<section class="page-header">
  <div class="badge">Settings</div>
  <h1>Configuracion</h1>
  <p>Ajusta los parametros de Mimosa y administra integraciones.</p>
</section>

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

{#if activeTab === 'blocking'}
  {#if error}
    <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
      <strong>Error</strong>
      <div style="color: var(--muted); margin-top: 4px;">{error}</div>
    </div>
  {/if}

  <div class="section">
    <div class="surface" style="padding: 18px; max-width: 520px;">
      {#if loading || !settings}
        <div> Cargando configuracion...</div>
      {:else}
        <div style="display: grid; gap: 12px;">
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
              Duracion por defecto (min)
            </div>
            <input type="number" min="1" bind:value={settings.default_duration_minutes} />
          </label>
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
              Intervalo de sincronizacion (seg)
            </div>
            <input type="number" min="30" bind:value={settings.sync_interval_seconds} />
          </label>
        </div>
        {#if message}
          <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
            {message}
          </div>
        {/if}
        <div style="margin-top: 16px; display: flex; gap: 10px;">
          <button class="primary" disabled={saving} on:click={saveSettings}>
            {saving ? 'Guardando...' : 'Guardar'}
          </button>
          <button class="ghost" on:click={loadSettings}>Recargar</button>
        </div>
      {/if}
    </div>
  </div>
{:else if activeTab === 'location'}
  <div class="section">
    <div class="surface" style="padding: 18px; max-width: 520px;">
      <div class="badge">Ubicacion</div>
      <h3 style="margin-top: 12px;">Posicion de Mimosa</h3>
      <p style="color: var(--muted); margin: 0 0 12px;">
        Selecciona en el minimapa la ubicacion para los rayos de ataque.
      </p>
      <LocationPicker bind:location={location} height={220} />
      <div style="margin-top: 10px; color: var(--muted); font-size: 12px;">
        {#if location}
          Lat: {location.lat.toFixed(5)} · Lon: {location.lon.toFixed(5)}
        {:else}
          Sin ubicacion definida.
        {/if}
      </div>
      {#if locationMessage}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
          {locationMessage}
        </div>
      {/if}
      {#if locationError}
        <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
          {locationError}
        </div>
      {/if}
      <div style="margin-top: 16px;">
        <button class="primary" disabled={savingLocation} on:click={saveLocation}>
          {savingLocation ? 'Guardando...' : 'Guardar ubicacion'}
        </button>
      </div>
    </div>
  </div>
{:else if activeTab === 'stats'}
  <div class="section">
    <div class="surface" style="padding: 18px; max-width: 520px;">
      <div class="badge">Estadisticas</div>
      <h3 style="margin-top: 12px;">Reiniciar base de datos</h3>
      <p style="color: var(--muted); margin: 0 0 12px;">
        Limpia contadores y tablas usadas para las graficas del dashboard.
      </p>
      {#if resetMessage}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
          {resetMessage}
        </div>
      {/if}
      {#if resetError}
        <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
          {resetError}
        </div>
      {/if}
      <div style="margin-top: 16px;">
        <button class="ghost" disabled={resetting} on:click={resetStats}>
          {resetting ? 'Reiniciando...' : 'Reiniciar estadisticas'}
        </button>
      </div>
    </div>
  </div>
{:else if activeTab === 'database'}
  <DatabaseSettings />
{:else if activeTab === 'telegram'}
  <TelegramBotSettings />
{:else if activeTab === 'firewall'}
  <FirewallAdminSettings />
{:else if activeTab === 'homeassistant'}
  <HomeAssistantSettings />
{/if}
