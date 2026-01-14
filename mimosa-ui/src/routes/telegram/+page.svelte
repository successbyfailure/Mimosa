<script lang="ts">
  import { onMount } from 'svelte';
  import { authStore } from '$lib/stores/auth';

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
      message = 'Configuración guardada correctamente';
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
    if (!confirm('¿Estás seguro de desautorizar este usuario?')) {
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
    if (!confirm('¿Estás seguro de eliminar este usuario?')) {
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

<svelte:head>
  <title>Bot de Telegram - Mimosa</title>
</svelte:head>

<div class="container">
  <div class="header">
    <div class="header-content">
      <div>
        <h1>🤖 Bot de Telegram</h1>
        <p class="subtitle">Gestiona el bot de Telegram para controlar Mimosa remotamente</p>
      </div>
      {#if config}
        <button
          class="btn-toggle-bot {config.enabled ? 'enabled' : 'disabled'}"
          on:click={toggleBot}
          title={config.enabled ? 'Desactivar bot' : 'Activar bot'}
        >
          {#if config.enabled}
            <span class="toggle-icon">🟢</span>
            <span class="toggle-text">Bot Activo</span>
          {:else}
            <span class="toggle-icon">🔴</span>
            <span class="toggle-text">Bot Inactivo</span>
          {/if}
        </button>
      {/if}
    </div>
  </div>

  {#if error}
    <div class="alert alert-error">{error}</div>
  {/if}

  {#if message}
    <div class="alert alert-success">{message}</div>
  {/if}

  <!-- Estadísticas -->
  {#if stats}
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{stats.authorized_users}</div>
        <div class="stat-label">Usuarios autorizados</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{stats.total_users}</div>
        <div class="stat-label">Total de usuarios</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{stats.total_interactions}</div>
        <div class="stat-label">Interacciones totales</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{stats.bot_enabled ? '✅' : '❌'}</div>
        <div class="stat-label">Estado del bot</div>
      </div>
    </div>
  {/if}

  <!-- Configuración del Bot -->
  <div class="card">
    <h2>⚙️ Configuración del Bot</h2>

    {#if loading}
      <p>Cargando...</p>
    {:else if config}
      <form on:submit|preventDefault={saveConfig}>
        <div class="form-group">
          <label for="enabled">
            <input type="checkbox" id="enabled" bind:checked={config.enabled} />
            Habilitar bot de Telegram
          </label>
          <p class="help-text">
            {#if config.enabled}
              El bot está <strong>habilitado</strong> y responderá a los comandos de usuarios autorizados.
            {:else}
              El bot está <strong>deshabilitado</strong> y no responderá a ningún comando.
            {/if}
          </p>
        </div>

        <div class="form-group">
          <label for="bot_token">Token del Bot</label>
          <div class="token-input-group">
            <input
              type={showToken ? 'text' : 'password'}
              id="bot_token"
              bind:value={config.bot_token}
              placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
              class="form-control"
            />
            <button type="button" class="btn-toggle" on:click={() => (showToken = !showToken)}>
              {showToken ? '🙈' : '👁️'}
            </button>
          </div>
          <p class="help-text">
            Obtén el token creando un bot con
            <a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer">@BotFather</a>
            en Telegram
          </p>
        </div>

        <div class="form-group">
          <label for="welcome_message">Mensaje de bienvenida</label>
          <textarea
            id="welcome_message"
            bind:value={config.welcome_message}
            rows="3"
            class="form-control"
          ></textarea>
          <p class="help-text">Mensaje que verán los usuarios autorizados al iniciar el bot</p>
        </div>

        <div class="form-group">
          <label for="unauthorized_message">Mensaje de no autorizado</label>
          <textarea
            id="unauthorized_message"
            bind:value={config.unauthorized_message}
            rows="3"
            class="form-control"
          ></textarea>
          <p class="help-text">Mensaje que verán los usuarios no autorizados</p>
        </div>

        <button type="submit" class="btn btn-primary" disabled={saving}>
          {saving ? 'Guardando...' : 'Guardar configuración'}
        </button>
      </form>
    {/if}
  </div>

  <!-- Usuarios Autorizados -->
  <div class="card">
    <h2>✅ Usuarios Autorizados</h2>

    {#if authorizedUsers.length === 0}
      <p class="empty-state">No hay usuarios autorizados. Los usuarios aparecerán aquí después de interactuar con el bot.</p>
    {:else}
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Usuario</th>
              <th>ID de Telegram</th>
              <th>Interacciones</th>
              <th>Última actividad</th>
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
                  <button class="btn btn-sm btn-warning" on:click={() => unauthorizeUser(user.telegram_id)}>
                    Desautorizar
                  </button>
                  <button class="btn btn-sm btn-danger" on:click={() => deleteUser(user.telegram_id)}>
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

  <!-- Usuarios No Autorizados -->
  {#if unauthorizedUsers.length > 0}
    <div class="card">
      <h2>⏳ Usuarios Pendientes de Autorización</h2>
      <p class="help-text">
        Estos usuarios han interactuado con el bot pero no están autorizados. Puedes autorizarlos aquí.
      </p>

      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>Usuario</th>
              <th>ID de Telegram</th>
              <th>Interacciones</th>
              <th>Primera vez</th>
              <th>Última actividad</th>
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
                  <button class="btn btn-sm btn-success" on:click={() => authorizeUser(user.telegram_id)}>
                    Autorizar
                  </button>
                  <button class="btn btn-sm btn-danger" on:click={() => deleteUser(user.telegram_id)}>
                    Eliminar
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {/if}

  <!-- Interacciones Recientes -->
  <div class="card">
    <h2>📜 Interacciones Recientes</h2>

    {#if interactions.length === 0}
      <p class="empty-state">No hay interacciones registradas.</p>
    {:else}
      <div class="table-responsive">
        <table class="data-table">
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
                    <span class="badge badge-success">Autorizado</span>
                  {:else}
                    <span class="badge badge-danger">No autorizado</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</div>

<style>
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  .header {
    margin-bottom: 2rem;
  }

  .header-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 2rem;
    flex-wrap: wrap;
  }

  .header h1 {
    font-size: 2rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
    color: #1a202c;
  }

  .subtitle {
    color: #718096;
    font-size: 1rem;
  }

  .btn-toggle-bot {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.75rem 1.5rem;
    border: 2px solid;
    border-radius: 0.5rem;
    font-weight: 600;
    font-size: 1rem;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .btn-toggle-bot.enabled {
    background: #c6f6d5;
    border-color: #48bb78;
    color: #22543d;
  }

  .btn-toggle-bot.enabled:hover {
    background: #9ae6b4;
    border-color: #38a169;
  }

  .btn-toggle-bot.disabled {
    background: #fed7d7;
    border-color: #f56565;
    color: #c53030;
  }

  .btn-toggle-bot.disabled:hover {
    background: #fc8181;
    border-color: #e53e3e;
  }

  .toggle-icon {
    font-size: 1.25rem;
  }

  .toggle-text {
    font-weight: 600;
  }

  .alert {
    padding: 1rem;
    border-radius: 0.5rem;
    margin-bottom: 1rem;
  }

  .alert-error {
    background-color: #fed7d7;
    color: #c53030;
    border: 1px solid #fc8181;
  }

  .alert-success {
    background-color: #c6f6d5;
    color: #22543d;
    border: 1px solid #68d391;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }

  .stat-card {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 0.5rem;
    padding: 1.5rem;
    text-align: center;
  }

  .stat-value {
    font-size: 2.5rem;
    font-weight: bold;
    color: #2d3748;
  }

  .stat-label {
    color: #718096;
    font-size: 0.875rem;
    margin-top: 0.5rem;
  }

  .card {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 0.5rem;
    padding: 2rem;
    margin-bottom: 2rem;
  }

  .card h2 {
    font-size: 1.5rem;
    font-weight: bold;
    margin-bottom: 1.5rem;
    color: #2d3748;
  }

  .form-group {
    margin-bottom: 1.5rem;
  }

  .form-group label {
    display: block;
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: #2d3748;
  }

  .form-control {
    width: 100%;
    padding: 0.5rem;
    border: 1px solid #cbd5e0;
    border-radius: 0.375rem;
    font-size: 1rem;
  }

  .form-control:focus {
    outline: none;
    border-color: #4299e1;
    box-shadow: 0 0 0 3px rgba(66, 153, 225, 0.1);
  }

  .token-input-group {
    display: flex;
    gap: 0.5rem;
  }

  .token-input-group input {
    flex: 1;
  }

  .btn-toggle {
    padding: 0.5rem 1rem;
    background: #edf2f7;
    border: 1px solid #cbd5e0;
    border-radius: 0.375rem;
    cursor: pointer;
  }

  .btn-toggle:hover {
    background: #e2e8f0;
  }

  .help-text {
    margin-top: 0.5rem;
    font-size: 0.875rem;
    color: #718096;
  }

  .help-text a {
    color: #4299e1;
    text-decoration: underline;
  }

  .btn {
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    font-weight: 600;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
  }

  .btn-primary {
    background: #4299e1;
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    background: #3182ce;
  }

  .btn-primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-sm {
    padding: 0.25rem 0.75rem;
    font-size: 0.875rem;
  }

  .btn-success {
    background: #48bb78;
    color: white;
  }

  .btn-success:hover {
    background: #38a169;
  }

  .btn-warning {
    background: #ed8936;
    color: white;
  }

  .btn-warning:hover {
    background: #dd6b20;
  }

  .btn-danger {
    background: #f56565;
    color: white;
  }

  .btn-danger:hover {
    background: #e53e3e;
  }

  .table-responsive {
    overflow-x: auto;
  }

  .data-table {
    width: 100%;
    border-collapse: collapse;
  }

  .data-table th,
  .data-table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid #e2e8f0;
  }

  .data-table th {
    background: #f7fafc;
    font-weight: 600;
    color: #2d3748;
  }

  .data-table tbody tr:hover {
    background: #f7fafc;
  }

  .data-table code {
    background: #edf2f7;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
    font-family: monospace;
    font-size: 0.875rem;
  }

  .message-cell {
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .badge {
    display: inline-block;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .badge-success {
    background: #c6f6d5;
    color: #22543d;
  }

  .badge-danger {
    background: #fed7d7;
    color: #c53030;
  }

  .empty-state {
    color: #718096;
    text-align: center;
    padding: 2rem;
  }
</style>
