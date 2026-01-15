<script lang="ts">
  import { onMount } from 'svelte';

  type HomeAssistantConfig = {
    enabled: boolean;
    api_token: string | null;
    expose_stats: boolean;
    expose_signals: boolean;
    expose_heatmap: boolean;
    heatmap_source: 'offenses' | 'blocks';
    heatmap_window: string;
    heatmap_limit: number;
    expose_rules: boolean;
    expose_firewall_rules: boolean;
    stats_include_timeline: boolean;
  };

  let config: HomeAssistantConfig | null = null;
  let loading = false;
  let saving = false;
  let error: string | null = null;
  let message: string | null = null;
  let tokenMessage: string | null = null;
  let showToken = false;

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

  const loadConfig = async () => {
    loading = true;
    error = null;
    tokenMessage = null;
    try {
      config = await requestJson<HomeAssistantConfig>('/api/homeassistant/config');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const saveConfig = async (rotateToken = false) => {
    if (!config) {
      return;
    }
    saving = true;
    error = null;
    message = null;
    tokenMessage = null;
    try {
      const payload = {
        ...config,
        rotate_token: rotateToken
      };
      const response = await requestJson<{ api_token?: string }>('/api/homeassistant/config', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      message = 'Configuracion guardada';
      if (rotateToken && response?.api_token) {
        config.api_token = response.api_token;
        tokenMessage = `Token rotado: ${response.api_token}`;
        showToken = true;
      }
      await loadConfig();
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo guardar';
    } finally {
      saving = false;
    }
  };

  onMount(() => {
    loadConfig();
  });
</script>

<div class="section">
  <div class="surface" style="padding: 18px; max-width: 640px;">
    <div class="badge">Home Assistant</div>
    <h3 style="margin-top: 12px;">Integracion REST</h3>
    <p style="color: var(--muted); margin: 0 0 12px;">
      Expone estadisticas, senales y heatmap para sensores y switches.
    </p>

    {#if loading || !config}
      <div>Cargando configuracion...</div>
    {:else}
      <div style="display: grid; gap: 12px;">
        <label style="display: flex; gap: 8px; align-items: center;">
          <input type="checkbox" bind:checked={config.enabled} />
          <span>Integracion habilitada</span>
        </label>

        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
            API token
          </div>
          <div style="display: flex; gap: 8px; align-items: center;">
            {#if showToken}
              <input
                type="text"
                placeholder="Token para Home Assistant"
                bind:value={config.api_token}
                style="flex: 1;"
              />
            {:else}
              <input
                type="password"
                placeholder="Token para Home Assistant"
                bind:value={config.api_token}
                style="flex: 1;"
              />
            {/if}
            <button class="ghost" type="button" on:click={() => (showToken = !showToken)}>
              {showToken ? 'Ocultar' : 'Mostrar'}
            </button>
          </div>
        </label>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px;">
          <label style="display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" bind:checked={config.expose_stats} />
            <span>Exponer estadisticas</span>
          </label>
          <label style="display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" bind:checked={config.expose_signals} />
            <span>Exponer senales</span>
          </label>
          <label style="display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" bind:checked={config.expose_heatmap} />
            <span>Exponer heatmap</span>
          </label>
          <label style="display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" bind:checked={config.expose_rules} />
            <span>Exponer reglas Mimosa</span>
          </label>
          <label style="display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" bind:checked={config.expose_firewall_rules} />
            <span>Exponer reglas firewall</span>
          </label>
          <label style="display: flex; gap: 8px; align-items: center;">
            <input type="checkbox" bind:checked={config.stats_include_timeline} />
            <span>Stats con timeline</span>
          </label>
        </div>

        <div style="display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));">
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
              Heatmap source
            </div>
            <select bind:value={config.heatmap_source}>
              <option value="offenses">Offenses</option>
              <option value="blocks">Blocks</option>
            </select>
          </label>
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
              Heatmap window
            </div>
            <select bind:value={config.heatmap_window}>
              <option value="24h">24h</option>
              <option value="7d">7d</option>
              <option value="30d">30d</option>
              <option value="total">total</option>
              <option value="current">current</option>
            </select>
          </label>
          <label>
            <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
              Heatmap limit
            </div>
            <input type="number" min="0" max="2000" bind:value={config.heatmap_limit} />
          </label>
        </div>
      </div>

      {#if message}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
          {message}
        </div>
      {/if}
      {#if tokenMessage}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
          {tokenMessage}
        </div>
      {/if}
      {#if error}
        <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
          {error}
        </div>
      {/if}

      <div style="margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap;">
        <button class="primary" disabled={saving} on:click={() => saveConfig(false)}>
          {saving ? 'Guardando...' : 'Guardar'}
        </button>
        <button class="ghost" disabled={saving} on:click={() => saveConfig(true)}>
          Rotar token
        </button>
        <button class="ghost" on:click={loadConfig}>Recargar</button>
      </div>

      <div style="margin-top: 16px; font-size: 12px; color: var(--muted);">
        Usa `Authorization: Bearer &lt;token&gt;` para consumir `/api/homeassistant/*`.
      </div>
    {/if}
  </div>
</div>
