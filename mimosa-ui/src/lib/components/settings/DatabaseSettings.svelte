<script lang="ts">
  import { onMount, onDestroy } from 'svelte';

  type MigrationState = {
    state?: string;
    message?: string;
    started_at?: string;
    finished_at?: string;
    details?: { counts?: Record<string, number> };
  };

  type DatabaseConfig = {
    backend: 'sqlite' | 'postgres';
    active_backend: string;
    postgres_url: string | null;
    postgres_ssl_required: boolean;
    postgres_allow_self_signed: boolean;
    sqlite_path: string;
    migration: MigrationState;
    restart_required: boolean;
  };

  let config: DatabaseConfig | null = null;
  let loading = false;
  let saving = false;
  let testing = false;
  let migrating = false;
  let error: string | null = null;
  let message: string | null = null;
  let urlMessage: string | null = null;
  let urlLoading = false;
  let showUrl = false;
  let postgresUrl = '';
  let pollInterval: number | undefined;

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
    try {
      config = await requestJson<DatabaseConfig>('/api/settings/database');
      if (config.postgres_allow_self_signed == null) {
        config.postgres_allow_self_signed = true;
      }
      postgresUrl = config.postgres_url || '';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const saveConfig = async () => {
    if (!config) {
      return;
    }
    saving = true;
    error = null;
    message = null;
    urlMessage = null;
    try {
      const payload = {
        backend: config.backend,
        postgres_url: postgresUrl,
        postgres_ssl_required: config.postgres_ssl_required,
        postgres_allow_self_signed: config.postgres_allow_self_signed
      };
      config = await requestJson<DatabaseConfig>('/api/settings/database', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      postgresUrl = config.postgres_url || postgresUrl;
      message = config.restart_required
        ? 'Configuracion guardada. Reinicia Mimosa para aplicar.'
        : 'Configuracion guardada';
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo guardar';
    } finally {
      saving = false;
    }
  };

  const testConnection = async () => {
    if (!config) {
      return;
    }
    testing = true;
    error = null;
    message = null;
    urlMessage = null;
    try {
      const payload = {
        backend: 'postgres',
        postgres_url: postgresUrl,
        postgres_ssl_required: config.postgres_ssl_required,
        postgres_allow_self_signed: config.postgres_allow_self_signed
      };
      await requestJson('/api/settings/database/test', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      message = 'Conexion exitosa';
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo conectar';
    } finally {
      testing = false;
    }
  };

  const startMigration = async () => {
    if (!config) {
      return;
    }
    if (!confirm('Migrar todos los datos desde SQLite a Postgres?')) {
      return;
    }
    migrating = true;
    error = null;
    message = null;
    urlMessage = null;
    try {
      await requestJson('/api/settings/database/migrate', { method: 'POST' });
      message = 'Migracion iniciada';
      await loadConfig();
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo iniciar la migracion';
    } finally {
      migrating = false;
    }
  };

  const loadUrl = async () => {
    urlLoading = true;
    error = null;
    urlMessage = null;
    try {
      const payload = await requestJson<{ postgres_url: string | null }>(
        '/api/settings/database/url'
      );
      if (!payload.postgres_url) {
        urlMessage = 'No hay URL configurada';
      } else {
        postgresUrl = payload.postgres_url;
      }
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo cargar la URL';
    } finally {
      urlLoading = false;
    }
  };

  const toggleUrl = async () => {
    if (showUrl) {
      showUrl = false;
      return;
    }
    await loadUrl();
    showUrl = true;
  };

  const stopPolling = () => {
    if (pollInterval) {
      window.clearInterval(pollInterval);
      pollInterval = undefined;
    }
  };

  $: if (config?.migration?.state === 'running') {
    if (!pollInterval) {
      pollInterval = window.setInterval(loadConfig, 4000);
    }
  } else {
    stopPolling();
  }

  onMount(() => {
    loadConfig();
  });

  onDestroy(() => {
    stopPolling();
  });
</script>

<div class="section">
  <div class="surface" style="padding: 18px; max-width: 720px;">
    <div class="badge">Database</div>
    <h3 style="margin-top: 12px;">SQLite / Postgres</h3>
    <p style="color: var(--muted); margin: 0 0 12px;">
      Configura Supabase/Postgres y migra todo el historial.
    </p>

    {#if loading || !config}
      <div>Cargando configuracion...</div>
    {:else}
      <div style="display: grid; gap: 12px;">
        <div style="display: grid; gap: 6px;">
          <div style="font-size: 12px; color: var(--muted);">Backend activo</div>
          <div>{config.active_backend}</div>
          {#if config.restart_required}
            <div style="color: var(--warning); font-size: 12px;">
              Reinicia Mimosa para aplicar el backend configurado.
            </div>
          {/if}
        </div>

        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
            Backend configurado
          </div>
          <select bind:value={config.backend}>
            <option value="sqlite">SQLite (local)</option>
            <option value="postgres">Postgres / Supabase</option>
          </select>
        </label>

        <label>
          <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
            URL de Postgres
          </div>
          {#if showUrl}
            <input
              type="text"
              placeholder="postgres://user:pass@host:5432/db"
              bind:value={postgresUrl}
            />
          {:else}
            <input
              type="password"
              placeholder="postgres://user:pass@host:5432/db"
              bind:value={postgresUrl}
            />
          {/if}
        </label>

        <label style="display: flex; gap: 8px; align-items: center;">
          <input type="checkbox" bind:checked={config.postgres_ssl_required} />
          <span>SSL requerido</span>
        </label>
        <label style="display: flex; gap: 8px; align-items: center;">
          <input type="checkbox" bind:checked={config.postgres_allow_self_signed} />
          <span>Allow self-signed</span>
        </label>

        <div style="font-size: 12px; color: var(--muted);">
          SQLite local: {config.sqlite_path}
        </div>
      </div>

      {#if config.migration}
        <div style="margin-top: 16px; font-size: 13px; color: var(--muted);">
          Estado migracion: {config.migration.state || 'idle'}
          {#if config.migration.message}
            <div>{config.migration.message}</div>
          {/if}
          {#if config.migration.started_at}
            <div>Inicio: {config.migration.started_at}</div>
          {/if}
          {#if config.migration.finished_at}
            <div>Fin: {config.migration.finished_at}</div>
          {/if}
          {#if config.migration.details?.counts}
            <div style="margin-top: 6px;">
              Tablas migradas: {Object.keys(config.migration.details.counts).length}
            </div>
          {/if}
        </div>
      {/if}

      {#if message}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
          {message}
        </div>
      {/if}
      {#if urlMessage}
        <div style="margin-top: 10px; color: var(--muted); font-size: 13px;">
          {urlMessage}
        </div>
      {/if}
      {#if error}
        <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
          {error}
        </div>
      {/if}

      <div style="margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap;">
        <button class="primary" disabled={saving} on:click={saveConfig}>
          {saving ? 'Guardando...' : 'Guardar'}
        </button>
        <button class="ghost" disabled={urlLoading} on:click={toggleUrl}>
          {urlLoading ? 'Cargando...' : showUrl ? 'Ocultar URL' : 'Mostrar URL'}
        </button>
        <button class="ghost" disabled={testing} on:click={testConnection}>
          {testing ? 'Probando...' : 'Probar conexion'}
        </button>
        <button class="ghost" disabled={migrating} on:click={startMigration}>
          {migrating ? 'Migrando...' : 'Migrar datos'}
        </button>
        <button class="ghost" on:click={loadConfig}>Recargar</button>
      </div>
    {/if}
  </div>
</div>
