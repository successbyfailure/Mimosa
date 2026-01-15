<script lang="ts">
  import { onMount } from 'svelte';

  type TelegramBotConfig = {
    enabled: boolean;
    bot_token: string | null;
    welcome_message: string;
    unauthorized_message: string;
  };

  type TelegramUser = {
    id: number;
    telegram_id: number;
    username: string | null;
    first_name: string | null;
    last_name: string | null;
    authorized: boolean;
    authorized_at: string | null;
    authorized_by: string | null;
    first_seen: string | null;
    last_seen: string | null;
    interaction_count: number;
  };

  type TelegramInteraction = {
    id: number;
    telegram_id: number;
    username: string | null;
    command: string | null;
    message: string | null;
    authorized: boolean;
    created_at: string;
  };

  type TelegramStats = {
    authorized_users: number;
    total_users: number;
    total_interactions: number;
    bot_enabled: boolean;
  };

  let config: TelegramBotConfig | null = null;
  let authorizedUsers: TelegramUser[] = [];
  let unauthorizedUsers: TelegramUser[] = [];
  let interactions: TelegramInteraction[] = [];
  let stats: TelegramStats | null = null;
  let loading = false;
  let error: string | null = null;
  let message: string | null = null;
  let saving = false;
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
    try {
      config = await requestJson<TelegramBotConfig>('/api/telegram/config');
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const loadUsers = async () => {
    try {
      const data = await requestJson<{ authorized: TelegramUser[]; unauthorized: TelegramUser[] }>(
        '/api/telegram/users'
      );
      authorizedUsers = data.authorized;
      unauthorizedUsers = data.unauthorized;
    } catch (err) {
      console.error('Error al cargar usuarios:', err);
    }
  };

  const loadInteractions = async () => {
    try {
      interactions = await requestJson<TelegramInteraction[]>('/api/telegram/interactions?limit=50');
    } catch (err) {
      console.error('Error al cargar interacciones:', err);
    }
  };

  const loadStats = async () => {
    try {
      stats = await requestJson<TelegramStats>('/api/telegram/stats');
    } catch (err) {
      console.error('Error al cargar estadísticas:', err);
    }
  };

  const saveConfig = async () => {
    if (!config) {
      return;
    }
    saving = true;
    error = null;
    message = null;
    try {
      await requestJson('/api/telegram/config', {
        method: 'PUT',
        body: JSON.stringify(config)
      });
      message = 'Configuracion guardada correctamente';
      await loadConfig();
      await loadStats();
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo guardar';
    } finally {
      saving = false;
    }
  };

  const authorizeUser = async (telegramId: number) => {
    try {
      await requestJson(`/api/telegram/users/${telegramId}/authorize`, {
        method: 'POST'
      });
      await loadUsers();
      await loadStats();
      message = 'Usuario autorizado correctamente';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error al autorizar usuario';
    }
  };

  const unauthorizeUser = async (telegramId: number) => {
    if (!confirm('¿Estas seguro de desautorizar este usuario?')) {
      return;
    }
    try {
      await requestJson(`/api/telegram/users/${telegramId}/unauthorize`, {
        method: 'POST'
      });
      await loadUsers();
      await loadStats();
      message = 'Usuario desautorizado correctamente';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error al desautorizar usuario';
    }
  };

  const deleteUser = async (telegramId: number) => {
    if (!confirm('¿Estas seguro de eliminar este usuario?')) {
      return;
    }
    try {
      await requestJson(`/api/telegram/users/${telegramId}`, {
        method: 'DELETE'
      });
      await loadUsers();
      await loadStats();
      message = 'Usuario eliminado correctamente';
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error al eliminar usuario';
    }
  };

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString('es-ES');
  };

  const getUserDisplayName = (user: TelegramUser) => {
    if (user.username) return `@${user.username}`;
    if (user.first_name) {
      return user.last_name ? `${user.first_name} ${user.last_name}` : user.first_name;
    }
    return `Usuario ${user.telegram_id}`;
  };

  const toggleBot = async () => {
    if (!config) return;

    error = null;
    message = null;
    try {
      const response = await requestJson<{ enabled: boolean; message: string }>(
        '/api/telegram/toggle',
        { method: 'POST' }
      );
      config.enabled = response.enabled;
      message = response.message;
      await loadStats();
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error al cambiar estado del bot';
    }
  };

  onMount(() => {
    loadConfig();
    loadUsers();
    loadInteractions();
    loadStats();
  });
</script>

<div class="telegram-page">
  <section class="page-header telegram-header">
    <div>
      <div class="badge">Telegram</div>
      <h1>Bot de Telegram</h1>
      <p>Gestiona el bot de Telegram para controlar Mimosa remotamente.</p>
    </div>
    {#if config}
      <button
        class="secondary telegram-toggle {config.enabled ? 'enabled' : 'disabled'}"
        on:click={toggleBot}
        title={config.enabled ? 'Desactivar bot' : 'Activar bot'}
      >
        <span class="toggle-dot"></span>
        <span>{config.enabled ? 'Bot activo' : 'Bot inactivo'}</span>
      </button>
    {/if}
  </section>

  {#if error}
    <div class="surface panel-sm telegram-alert telegram-alert-error">
      <strong>Error</strong>
      <div class="telegram-alert-text">{error}</div>
    </div>
  {/if}

  {#if message}
    <div class="surface panel-sm telegram-alert telegram-alert-success">
      <strong>Listo</strong>
      <div class="telegram-alert-text">{message}</div>
    </div>
  {/if}

  {#if stats}
    <section class="section">
      <div class="card-grid">
        <div class="surface panel kpi">
          <strong>{stats.authorized_users}</strong>
          <span>Usuarios autorizados</span>
        </div>
        <div class="surface panel kpi">
          <strong>{stats.total_users}</strong>
          <span>Total de usuarios</span>
        </div>
        <div class="surface panel kpi">
          <strong>{stats.total_interactions}</strong>
          <span>Interacciones totales</span>
        </div>
        <div class="surface panel kpi">
          <strong class={stats.bot_enabled ? 'status-on' : 'status-off'}>
            {stats.bot_enabled ? 'Activo' : 'Inactivo'}
          </strong>
          <span>Estado del bot</span>
        </div>
      </div>
    </section>
  {/if}

  <section class="section">
    <div class="surface panel">
      <div class="badge">Configuracion</div>
      <h2 class="card-title">Configuracion del Bot</h2>

    {#if loading}
      <p>Cargando...</p>
    {:else if config}
      <form on:submit|preventDefault={saveConfig} class="form-grid">
        <div class="toggle-row">
          <input type="checkbox" id="enabled" bind:checked={config.enabled} />
          <div>
            <label class="toggle-label" for="enabled">Habilitar bot de Telegram</label>
            <p class="help-text">
              {#if config.enabled}
                El bot esta <strong>habilitado</strong> y respondera a los comandos de usuarios autorizados.
              {:else}
                El bot esta <strong>deshabilitado</strong> y no respondera a ningun comando.
              {/if}
            </p>
          </div>
        </div>

        <div>
          <label class="field-label" for="bot_token">Token del Bot</label>
          <div class="token-input-group">
            {#if showToken}
              <input
                type="text"
                id="bot_token"
                bind:value={config.bot_token}
                placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
              />
            {:else}
              <input
                type="password"
                id="bot_token"
                bind:value={config.bot_token}
                placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
              />
            {/if}
            <button type="button" class="ghost token-toggle" on:click={() => (showToken = !showToken)}>
              {showToken ? '🙈' : '👁️'}
            </button>
          </div>
          <p class="help-text">
            Obten el token creando un bot con
            <a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer">@BotFather</a>
            en Telegram.
          </p>
        </div>

        <div class="form-row">
          <div>
            <label class="field-label" for="welcome_message">Mensaje de bienvenida</label>
            <textarea id="welcome_message" bind:value={config.welcome_message} rows="3"></textarea>
            <p class="help-text">Mensaje que veran los usuarios autorizados al iniciar el bot.</p>
          </div>
          <div>
            <label class="field-label" for="unauthorized_message">Mensaje de no autorizado</label>
            <textarea
              id="unauthorized_message"
              bind:value={config.unauthorized_message}
              rows="3"
            ></textarea>
            <p class="help-text">Mensaje que veran los usuarios no autorizados.</p>
          </div>
        </div>

        <div class="card-actions">
          <button type="submit" class="primary" disabled={saving}>
            {saving ? 'Guardando...' : 'Guardar configuracion'}
          </button>
        </div>
      </form>
    {/if}
    </div>
  </section>

  <section class="section">
    <div class="surface panel">
      <div class="badge">Usuarios</div>
      <h2 class="card-title">Usuarios Autorizados</h2>

    {#if authorizedUsers.length === 0}
      <p class="empty-state">No hay usuarios autorizados. Los usuarios apareceran aqui despues de interactuar con el bot.</p>
    {:else}
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive table-compact">
          <thead>
            <tr>
              <th>Usuario</th>
              <th>ID de Telegram</th>
              <th>Interacciones</th>
              <th>Ultima actividad</th>
              <th>Autorizado por</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {#each authorizedUsers as user}
              <tr>
                <td>{getUserDisplayName(user)}</td>
                <td><code>{user.telegram_id}</code></td>
                <td>{user.interaction_count}</td>
                <td>{formatDate(user.last_seen)}</td>
                <td>{user.authorized_by || 'N/A'}</td>
                <td>
                  <button class="ghost btn-sm" on:click={() => unauthorizeUser(user.telegram_id)}>
                    Desautorizar
                  </button>
                  <button class="ghost btn-sm danger" on:click={() => deleteUser(user.telegram_id)}>
                    Eliminar
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    </div>
  </section>

  {#if unauthorizedUsers.length > 0}
    <section class="section">
      <div class="surface panel">
        <div class="badge badge-muted">Pendientes</div>
        <h2 class="card-title">Usuarios Pendientes de Autorizacion</h2>
      <p class="help-text">
        Estos usuarios han interactuado con el bot pero no estan autorizados. Puedes autorizarlos aqui.
      </p>

      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive table-compact">
          <thead>
            <tr>
              <th>Usuario</th>
              <th>ID de Telegram</th>
              <th>Interacciones</th>
              <th>Primera vez</th>
              <th>Ultima actividad</th>
              <th>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {#each unauthorizedUsers as user}
              <tr>
                <td>{getUserDisplayName(user)}</td>
                <td><code>{user.telegram_id}</code></td>
                <td>{user.interaction_count}</td>
                <td>{formatDate(user.first_seen)}</td>
                <td>{formatDate(user.last_seen)}</td>
                <td>
                  <button class="secondary btn-sm" on:click={() => authorizeUser(user.telegram_id)}>
                    Autorizar
                  </button>
                  <button class="ghost btn-sm danger" on:click={() => deleteUser(user.telegram_id)}>
                    Eliminar
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      </div>
    </section>
  {/if}

  <section class="section">
    <div class="surface panel">
      <div class="badge">Actividad</div>
      <h2 class="card-title">Interacciones Recientes</h2>

    {#if interactions.length === 0}
      <p class="empty-state">No hay interacciones registradas.</p>
    {:else}
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive table-compact">
          <thead>
            <tr>
              <th>Fecha</th>
              <th>Usuario</th>
              <th>Comando</th>
              <th>Mensaje</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            {#each interactions as interaction}
              <tr>
                <td>{formatDate(interaction.created_at)}</td>
                <td>{interaction.username ? `@${interaction.username}` : `ID: ${interaction.telegram_id}`}</td>
                <td><code>{interaction.command || '-'}</code></td>
                <td class="message-cell">{interaction.message || '-'}</td>
                <td>
                  {#if interaction.authorized}
                    <span class="tag tag-success">Autorizado</span>
                  {:else}
                    <span class="tag tag-danger">No autorizado</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
    </div>
  </section>
</div>

<style>
  .telegram-page {
    padding: var(--space-5);
  }

  .telegram-header {
    display: flex;
    justify-content: space-between;
    gap: var(--space-4);
    align-items: center;
    flex-wrap: wrap;
  }

  .telegram-toggle {
    gap: 10px;
  }

  .telegram-toggle.enabled {
    border-color: rgba(45, 212, 191, 0.5);
  }

  .telegram-toggle.disabled {
    border-color: rgba(248, 113, 113, 0.5);
  }

  .telegram-toggle.enabled .toggle-dot {
    background: var(--success);
  }

  .telegram-toggle.disabled .toggle-dot {
    background: var(--danger);
  }

  .telegram-alert {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .telegram-alert-error {
    border-color: rgba(248, 113, 113, 0.5);
  }

  .telegram-alert-success {
    border-color: rgba(34, 197, 94, 0.4);
  }

  .telegram-alert-text {
    color: var(--muted);
  }

  .token-input-group {
    display: flex;
    align-items: stretch;
    gap: 8px;
  }

  .token-input-group input {
    flex: 1;
  }

  .token-toggle {
    width: 40px;
    height: 40px;
  }

  .form-grid {
    display: grid;
    gap: 16px;
    margin-top: 12px;
  }

  .form-row {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
  }

  .toggle-row {
    display: flex;
    gap: 12px;
    align-items: flex-start;
  }

  .toggle-label {
    font-weight: 600;
  }

  .help-text {
    color: var(--muted);
    font-size: 12px;
    margin-top: 4px;
  }

  .card-actions {
    display: flex;
    justify-content: flex-end;
  }

  .message-cell {
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  @media (max-width: 860px) {
    .telegram-page {
      padding: var(--space-4);
    }
  }
</style>
