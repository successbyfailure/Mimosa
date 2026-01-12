<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authStore } from '$lib/stores/auth';

  onMount(() => {
    authStore.checkSession();
  });

  $: isLogin = $page.url.pathname.startsWith('/login');
  $: isPublicHome = $page.url.pathname === '/';
  $: if (!isLogin && !isPublicHome && !$authStore.loading && !$authStore.user) {
    const next = encodeURIComponent(`${$page.url.pathname}${$page.url.search}`);
    goto(`/login?next=${next}`);
  }
</script>

{#if isLogin || (isPublicHome && !$authStore.user)}
  <slot />
{:else}
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        Mimosa
        <span>Defense Core</span>
      </div>
      <nav class="nav-links">
        <a href="/" class={$page.url.pathname === '/' ? 'active' : ''}>Dashboard</a>
        <a
          href="/offenses"
          class={$page.url.pathname.startsWith('/offenses') ? 'active' : ''}
        >
          Offenses
        </a>
        <a href="/blocks" class={$page.url.pathname.startsWith('/blocks') ? 'active' : ''}>
          Blocks
        </a>
        <a
          href="/whitelist"
          class={$page.url.pathname.startsWith('/whitelist') ? 'active' : ''}
        >
          Whitelist
        </a>
        <a href="/ips" class={$page.url.pathname.startsWith('/ips') ? 'active' : ''}>
          IPs
        </a>
        <a href="/rules" class={$page.url.pathname.startsWith('/rules') ? 'active' : ''}>
          Rules
        </a>
        <a
          href="/plugins"
          class={$page.url.pathname.startsWith('/plugins') ? 'active' : ''}
        >
          Plugins
        </a>
        <a
          href="/firewall"
          class={$page.url.pathname.startsWith('/firewall') ? 'active' : ''}
        >
          Firewall
        </a>
        <a
          href="/settings"
          class={$page.url.pathname.startsWith('/settings') ? 'active' : ''}
        >
          Settings
        </a>
        <a href="/admin" class={$page.url.pathname.startsWith('/admin') ? 'active' : ''}>
          Admin
        </a>
      </nav>
      <div class="section">
        <div class="surface" style="padding: 16px;">
          <div class="badge">Sesion</div>
          <div style="margin-top: 8px; color: var(--muted); font-size: 13px;">
            {#if $authStore.user}
              {$authStore.user.username} - {$authStore.user.role}
            {:else}
              Invitado
            {/if}
          </div>
          <div style="margin-top: 12px;">
            {#if $authStore.user}
              <button class="ghost" on:click={() => authStore.logout()}>Cerrar sesion</button>
            {:else}
              <a class="ghost" href="/login">Iniciar sesion</a>
            {/if}
          </div>
        </div>
      </div>
    </aside>
    <main class="main">
      <slot />
    </main>
  </div>
{/if}
