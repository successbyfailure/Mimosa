<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authStore } from '$lib/stores/auth';

  let username = '';
  let password = '';
  let error: string | null = null;

  $: nextParam = $page.url.searchParams.get('next') ?? '/';
  $: redirectPath = nextParam.startsWith('/') ? nextParam : '/';

  const submit = async () => {
    error = null;
    try {
      await authStore.login(username, password);
      goto(redirectPath);
    } catch (err) {
      error = err instanceof Error ? err.message : 'Credenciales invalidas';
    }
  };

  $: if ($authStore.user) {
    goto(redirectPath);
  }
</script>

<div
  style="
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 24px;
  "
>
  <div class="surface" style="padding: 32px; width: min(420px, 92vw);">
    <div class="badge">Acceso</div>
    <h2 style="margin: 16px 0 6px;">Inicia sesion en Mimosa</h2>
    <p style="color: var(--muted); margin: 0 0 20px;">
      Usa tus credenciales de administrador para continuar.
    </p>
    <div style="display: grid; gap: 12px;">
      <label>
        <div style="font-size: 12px; margin-bottom: 6px; color: var(--muted);">Usuario</div>
        <input placeholder="mimosa" bind:value={username} />
      </label>
      <label>
        <div style="font-size: 12px; margin-bottom: 6px; color: var(--muted);">Contrasena</div>
        <input type="password" bind:value={password} />
      </label>
    </div>
    {#if error}
      <div style="margin-top: 12px; color: var(--danger); font-size: 13px;">{error}</div>
    {/if}
    <div style="margin-top: 20px; display: flex; gap: 12px;">
      <button class="primary" on:click|preventDefault={submit}>
        {#if $authStore.loading}Entrando...{:else}Entrar{/if}
      </button>
      <a class="ghost" href="/">Volver</a>
    </div>
  </div>
</div>
