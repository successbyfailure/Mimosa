<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type User = {
    username: string;
    role: string;
    created_at: string;
  };

  type FirewallStatus = {
    id: string;
    name: string;
    type: string;
    enabled: boolean;
    online: boolean;
    message: string;
    alias_ready?: boolean;
    alias_created?: boolean;
    applied_changes?: boolean;
  };

  type FirewallConfig = {
    id: string;
    name: string;
    type: 'opnsense' | 'pfsense';
    base_url?: string | null;
    api_key?: string | null;
    api_secret?: string | null;
    enabled?: boolean;
    verify_ssl?: boolean;
    timeout?: number;
    apply_changes?: boolean;
  };

  type FirewallForm = {
    name: string;
    type: 'opnsense' | 'pfsense';
    base_url: string;
    api_key: string;
    api_secret: string;
    enabled: boolean;
    verify_ssl: boolean;
    timeout: number;
    apply_changes: boolean;
  };

  let users: User[] = [];
  let firewalls: FirewallConfig[] = [];
  let statuses: FirewallStatus[] = [];
  let loading = false;
  let error: string | null = null;
  let loaded = false;

  let form: FirewallForm = {
    name: '',
    type: 'opnsense',
    base_url: '',
    api_key: '',
    api_secret: '',
    enabled: true,
    verify_ssl: true,
    timeout: 5,
    apply_changes: true
  };
  let editingId: string | null = null;
  let actionMessage: string | null = null;
  let actionError: string | null = null;
  let actionLoading = false;

  type NewUserForm = {
    username: string;
    password: string;
    role: 'admin' | 'viewer';
  };

  let newUser: NewUserForm = {
    username: '',
    password: '',
    role: 'viewer'
  };

  let userEdits: Record<string, { role: string; password: string }> = {};
  let userMessage: string | null = null;
  let userError: string | null = null;
  let userLoading = false;

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

  const loadAdminData = async () => {
    loading = true;
    error = null;
    try {
      const [usersResult, statusResult, firewallsResult] = await Promise.allSettled([
        requestJson<User[]>('/api/users'),
        requestJson<FirewallStatus[]>('/api/firewalls/status'),
        requestJson<FirewallConfig[]>('/api/firewalls')
      ]);

      if (usersResult.status === 'fulfilled') {
        users = usersResult.value;
        userEdits = usersResult.value.reduce((acc, user) => {
          acc[user.username] = { role: user.role as 'admin' | 'viewer', password: '' };
          return acc;
        }, {} as Record<string, { role: string; password: string }>);
      } else {
        users = [];
        error = usersResult.reason?.message || 'No se pudieron cargar usuarios';
      }

      if (statusResult.status === 'fulfilled') {
        statuses = statusResult.value;
      } else if (!error) {
        error = statusResult.reason?.message || 'No se pudieron cargar estados';
      }

      if (firewallsResult.status === 'fulfilled') {
        firewalls = firewallsResult.value;
      } else if (!error) {
        error = firewallsResult.reason?.message || 'No se pudieron cargar firewalls';
      }
    } catch (err) {
      error = err instanceof Error ? err.message : 'Error inesperado';
    } finally {
      loading = false;
    }
  };

  const statusFor = (id: string) => statuses.find((status) => status.id === id);

  const resetForm = () => {
    form = {
      name: '',
      type: 'opnsense',
      base_url: '',
      api_key: '',
      api_secret: '',
      enabled: true,
      verify_ssl: true,
      timeout: 5,
      apply_changes: true
    };
    editingId = null;
  };

  const cancelEdit = () => {
    resetForm();
    actionMessage = null;
    actionError = null;
  };

  const editFirewall = (firewall: FirewallConfig) => {
    editingId = firewall.id;
    form = {
      name: firewall.name,
      type: firewall.type,
      base_url: firewall.base_url || '',
      api_key: firewall.api_key || '',
      api_secret: firewall.api_secret || '',
      enabled: firewall.enabled ?? true,
      verify_ssl: firewall.verify_ssl ?? true,
      timeout: firewall.timeout ?? 5,
      apply_changes: firewall.apply_changes ?? true
    };
    actionMessage = null;
    actionError = null;
  };

  const saveFirewall = async () => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const payload = {
        name: form.name.trim(),
        type: form.type,
        base_url: form.base_url.trim() || null,
        api_key: form.api_key.trim() || null,
        api_secret: form.api_secret.trim() || null,
        enabled: form.enabled,
        verify_ssl: form.verify_ssl,
        timeout: Number(form.timeout) || 5,
        apply_changes: form.apply_changes
      };

      if (!payload.name) {
        throw new Error('Nombre obligatorio');
      }

      if (editingId) {
        await requestJson(`/api/firewalls/${editingId}`, {
          method: 'PUT',
          body: JSON.stringify(payload)
        });
        actionMessage = 'Firewall actualizado';
      } else {
        await requestJson('/api/firewalls', {
          method: 'POST',
          body: JSON.stringify(payload)
        });
        actionMessage = 'Firewall creado';
      }

      await loadAdminData();
      resetForm();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo guardar';
    } finally {
      actionLoading = false;
    }
  };

  const deleteFirewall = async (firewall: FirewallConfig) => {
    if (!confirm(`Eliminar firewall ${firewall.name}?`)) {
      return;
    }
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      await requestJson(`/api/firewalls/${firewall.id}`, { method: 'DELETE' });
      actionMessage = 'Firewall eliminado';
      await loadAdminData();
      if (editingId === firewall.id) {
        resetForm();
      }
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo eliminar';
    } finally {
      actionLoading = false;
    }
  };

  const testFirewall = async (firewall?: FirewallConfig) => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const payload = firewall
        ? {
            name: firewall.name,
            type: firewall.type,
            base_url: firewall.base_url || null,
            api_key: firewall.api_key || null,
            api_secret: firewall.api_secret || null,
            enabled: firewall.enabled ?? true,
            verify_ssl: firewall.verify_ssl ?? true,
            timeout: firewall.timeout ?? 5,
            apply_changes: firewall.apply_changes ?? true
          }
        : {
            name: form.name.trim(),
            type: form.type,
            base_url: form.base_url.trim() || null,
            api_key: form.api_key.trim() || null,
            api_secret: form.api_secret.trim() || null,
            enabled: form.enabled,
            verify_ssl: form.verify_ssl,
            timeout: Number(form.timeout) || 5,
            apply_changes: form.apply_changes
          };

      const result = await requestJson<{ online: boolean; message: string }>(
        '/api/firewalls/test',
        {
          method: 'POST',
          body: JSON.stringify(payload)
        }
      );
      actionMessage = result.online ? 'Conexion OK' : result.message || 'Sin respuesta';
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo probar';
    } finally {
      actionLoading = false;
    }
  };

  const toggleFirewall = async (firewall: FirewallConfig, enabled: boolean) => {
    actionLoading = true;
    actionMessage = null;
    actionError = null;
    try {
      const payload = {
        name: firewall.name,
        type: firewall.type,
        base_url: firewall.base_url || null,
        api_key: firewall.api_key || null,
        api_secret: firewall.api_secret || null,
        enabled,
        verify_ssl: firewall.verify_ssl ?? true,
        timeout: firewall.timeout ?? 5,
        apply_changes: firewall.apply_changes ?? true
      };
      await requestJson(`/api/firewalls/${firewall.id}`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      actionMessage = enabled ? 'Firewall activado' : 'Firewall desactivado';
      await loadAdminData();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'No se pudo actualizar';
    } finally {
      actionLoading = false;
    }
  };

  const updateUserRole = (username: string, role: string) => {
    const current = userEdits[username] || { role: 'viewer', password: '' };
    userEdits = { ...userEdits, [username]: { ...current, role } };
  };

  const updateUserPassword = (username: string, password: string) => {
    const current = userEdits[username] || { role: 'viewer', password: '' };
    userEdits = { ...userEdits, [username]: { ...current, password } };
  };

  const handleRoleChange = (username: string, event: Event) => {
    const value = (event.target as HTMLSelectElement).value;
    updateUserRole(username, value);
  };

  const handlePasswordChange = (username: string, event: Event) => {
    const value = (event.target as HTMLInputElement).value;
    updateUserPassword(username, value);
  };

  const createUser = async () => {
    userLoading = true;
    userMessage = null;
    userError = null;
    try {
      const payload = {
        username: newUser.username.trim(),
        password: newUser.password.trim(),
        role: newUser.role
      };
      if (!payload.username || !payload.password) {
        throw new Error('Usuario y contrasena son obligatorios');
      }
      await requestJson('/api/users', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      userMessage = 'Usuario creado';
      newUser = { username: '', password: '', role: 'viewer' };
      await loadAdminData();
    } catch (err) {
      userError = err instanceof Error ? err.message : 'No se pudo crear usuario';
    } finally {
      userLoading = false;
    }
  };

  const saveUser = async (user: User) => {
    userLoading = true;
    userMessage = null;
    userError = null;
    try {
      const edit = userEdits[user.username];
      const payload: { password?: string; role?: string } = {};
      if (edit?.password) {
        payload.password = edit.password;
      }
      if (edit?.role && edit.role !== user.role) {
        payload.role = edit.role;
      }
      if (!payload.password && !payload.role) {
        userMessage = 'Sin cambios';
        return;
      }
      await requestJson(`/api/users/${user.username}`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      userMessage = 'Usuario actualizado';
      await loadAdminData();
    } catch (err) {
      userError = err instanceof Error ? err.message : 'No se pudo actualizar';
    } finally {
      userLoading = false;
    }
  };

  const deleteUser = async (user: User) => {
    if (!confirm(`Eliminar usuario ${user.username}?`)) {
      return;
    }
    userLoading = true;
    userMessage = null;
    userError = null;
    try {
      await requestJson(`/api/users/${user.username}`, { method: 'DELETE' });
      userMessage = 'Usuario eliminado';
      await loadAdminData();
    } catch (err) {
      userError = err instanceof Error ? err.message : 'No se pudo eliminar';
    } finally {
      userLoading = false;
    }
  };

  $: isAdmin = $authStore.user?.role === 'admin';

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  $: if (!$authStore.loading && isAdmin && !loaded) {
    loaded = true;
    loadAdminData();
  }

  onMount(() => {
    if (isAdmin && !loaded) {
      loaded = true;
      loadAdminData();
    }
  });
</script>

<section class="page-header">
  <div class="badge">Firewall</div>
  <h1>Gestion de firewalls</h1>
  <p>Administra firewalls y accesos desde Settings.</p>
</section>

{#if !isAdmin && !$authStore.loading && $authStore.user}
  <div class="surface" style="padding: 18px;">
    <strong>Acceso restringido</strong>
    <p style="color: var(--muted); margin-top: 6px;">
      Solo administradores pueden gestionar usuarios y firewalls.
    </p>
  </div>
{:else}
  {#if error}
    <div class="surface" style="padding: 16px; border-color: rgba(248, 113, 113, 0.5);">
      <strong>Error</strong>
      <div style="color: var(--muted); margin-top: 4px;">{error}</div>
    </div>
  {/if}

  <div class="section">
    <div class="surface" style="padding: 18px;">
      <div class="badge">Firewalls</div>
      <h3 style="margin-top: 12px;">Configuracion</h3>
      <div class="split" style="margin-top: 16px;">
        <div>
          <div class="list">
            {#if loading}
              <div class="list-item">Cargando firewalls...</div>
            {:else if firewalls.length === 0}
              <div class="list-item">No hay firewalls configurados.</div>
            {:else}
              {#each firewalls as firewall}
                {@const status = statusFor(firewall.id)}
                <div class="list-item" style="align-items: flex-start;">
                  <div style="max-width: 60%;">
                    <div style="font-weight: 600;">{firewall.name}</div>
                    <div style="color: var(--muted); font-size: 12px;">
                      {firewall.type} - {firewall.base_url || 'sin URL'}
                    </div>
                    {#if status}
                      <div style="color: var(--muted); font-size: 12px; margin-top: 4px;">
                        {status.message}
                      </div>
                    {/if}
                  </div>
                  <div style="display: grid; gap: 6px; justify-items: end;">
                    <strong
                      style="color: {firewall.enabled ? (status?.online ? 'var(--success)' : 'var(--danger)') : 'var(--warning)'};"
                    >
                      {firewall.enabled ? (status?.online ? 'Online' : 'Offline') : 'Inactivo'}
                    </strong>
                    <div style="display: flex; gap: 6px;">
                      <button
                        class="ghost"
                        disabled={actionLoading}
                        on:click={() => toggleFirewall(firewall, !firewall.enabled)}
                      >
                        {firewall.enabled ? 'Desactivar' : 'Activar'}
                      </button>
                      <button class="ghost" on:click={() => editFirewall(firewall)}>
                        Editar
                      </button>
                      <button class="ghost" on:click={() => testFirewall(firewall)}>
                        Probar
                      </button>
                      <button class="ghost" on:click={() => deleteFirewall(firewall)}>
                        Borrar
                      </button>
                    </div>
                  </div>
                </div>
              {/each}
            {/if}
          </div>
        </div>
        <div class="surface" style="padding: 16px; border: 1px solid var(--border);">
          <div style="font-weight: 600;">
            {editingId ? 'Editar firewall' : 'Nuevo firewall'}
          </div>
          <div style="display: grid; gap: 12px; margin-top: 12px;">
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Nombre</div>
              <input bind:value={form.name} placeholder="Mi firewall" />
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Tipo</div>
              <select bind:value={form.type} class="ghost" style="width: 100%; padding: 10px;">
                <option value="opnsense">OPNsense</option>
                <option value="pfsense">pfSense</option>
              </select>
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Base URL</div>
              <input bind:value={form.base_url} placeholder="https://firewall.local" />
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">API Key</div>
              <input bind:value={form.api_key} placeholder="API key" />
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
                API Secret
              </div>
              <input bind:value={form.api_secret} placeholder="API secret" />
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Timeout</div>
              <input type="number" min="1" step="1" bind:value={form.timeout} />
            </label>
            <label style="display: flex; align-items: center; gap: 8px;">
              <input type="checkbox" bind:checked={form.verify_ssl} />
              <span>Verificar SSL</span>
            </label>
            <label style="display: flex; align-items: center; gap: 8px;">
              <input type="checkbox" bind:checked={form.enabled} />
              <span>Activo</span>
            </label>
            <label style="display: flex; align-items: center; gap: 8px;">
              <input type="checkbox" bind:checked={form.apply_changes} />
              <span>Aplicar cambios</span>
            </label>
          </div>
          {#if actionMessage}
            <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
              {actionMessage}
            </div>
          {/if}
          {#if actionError}
            <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
              {actionError}
            </div>
          {/if}
          <div style="margin-top: 16px; display: flex; gap: 10px; flex-wrap: wrap;">
            <button class="primary" disabled={actionLoading} on:click={saveFirewall}>
              {actionLoading ? 'Guardando...' : 'Guardar'}
            </button>
            <button class="ghost" disabled={actionLoading} on:click={() => testFirewall()}>
              {actionLoading ? 'Probando...' : 'Probar'}
            </button>
            {#if editingId}
              <button class="ghost" disabled={actionLoading} on:click={cancelEdit}>
                Cancelar
              </button>
            {/if}
          </div>
        </div>
      </div>
    </div>

    <div class="surface" style="padding: 18px;">
      <div class="badge">Usuarios</div>
      <h3 style="margin-top: 12px;">Accesos registrados</h3>
      <div class="split" style="margin-top: 16px;">
        <div style="overflow-x: auto;">
          <table class="table table-responsive">
            <thead>
              <tr>
                <th>Usuario</th>
                <th>Rol</th>
                <th>Reset</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#if loading}
                <tr>
                  <td colspan="4">Cargando usuarios...</td>
                </tr>
              {:else if users.length === 0}
                <tr>
                  <td colspan="4">Sin usuarios.</td>
                </tr>
              {:else}
                {#each users as user}
                  <tr>
                    <td data-label="Usuario">{user.username}</td>
                    <td data-label="Rol" style="min-width: 140px;">
                      <select
                        value={userEdits[user.username]?.role || user.role}
                        on:change={(event) => handleRoleChange(user.username, event)}
                      >
                        <option value="admin">Admin</option>
                        <option value="viewer">Viewer</option>
                      </select>
                    </td>
                    <td data-label="Reset" style="min-width: 160px;">
                      <input
                        type="password"
                        placeholder="Nueva contrasena"
                        value={userEdits[user.username]?.password || ''}
                        on:input={(event) => handlePasswordChange(user.username, event)}
                      />
                    </td>
                    <td data-label="Accion" style="min-width: 200px;">
                      <div style="display: flex; gap: 8px;">
                        <button class="ghost" disabled={userLoading} on:click={() => saveUser(user)}>
                          Guardar
                        </button>
                        <button class="ghost" disabled={userLoading} on:click={() => deleteUser(user)}>
                          Borrar
                        </button>
                      </div>
                    </td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
          {#if userMessage}
            <div style="margin-top: 10px; color: var(--success); font-size: 13px;">
              {userMessage}
            </div>
          {/if}
          {#if userError}
            <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">
              {userError}
            </div>
          {/if}
        </div>
        <div class="surface" style="padding: 16px; border: 1px solid var(--border);">
          <div style="font-weight: 600;">Nuevo usuario</div>
          <div style="display: grid; gap: 12px; margin-top: 12px;">
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Usuario</div>
              <input bind:value={newUser.username} placeholder="usuario" />
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">
                Contrasena
              </div>
              <input type="password" bind:value={newUser.password} placeholder="segura" />
            </label>
            <label>
              <div style="font-size: 12px; color: var(--muted); margin-bottom: 4px;">Rol</div>
              <select bind:value={newUser.role}>
                <option value="admin">Admin</option>
                <option value="viewer">Viewer</option>
              </select>
            </label>
          </div>
          <div style="margin-top: 16px;">
            <button class="primary" disabled={userLoading} on:click={createUser}>
              {userLoading ? 'Guardando...' : 'Crear usuario'}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
{/if}
