<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { authStore } from '$lib/stores/auth';

  onMount(() => {
    authStore.checkSession();
  });

  let sidebarOpen = true;
  let logoPulse = false;
  let logoPulseTimer: number | null = null;

  onMount(() => {
    if (typeof window !== 'undefined') {
      sidebarOpen = window.innerWidth > 900;
    }
    const handleOffense = () => {
      logoPulse = false;
      if (logoPulseTimer) {
        window.clearTimeout(logoPulseTimer);
      }
      logoPulse = true;
      logoPulseTimer = window.setTimeout(() => {
        logoPulse = false;
        logoPulseTimer = null;
      }, 900);
    };
    window.addEventListener('mimosa:offense', handleOffense);
    return () => {
      window.removeEventListener('mimosa:offense', handleOffense);
      if (logoPulseTimer) {
        window.clearTimeout(logoPulseTimer);
      }
    };
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
  <div class={`app-shell ${sidebarOpen ? '' : 'collapsed'}`}>
    <aside class={`sidebar ${sidebarOpen ? '' : 'collapsed'}`}>
      <button
        class="brand brand-toggle"
        type="button"
        on:click={() => (sidebarOpen = !sidebarOpen)}
        aria-label="Abrir menu"
      >
        <span class={`brand-logo mimosa-mark ${logoPulse ? 'pulse' : ''}`} aria-hidden="true">
          <svg class="mimosa-leaf-svg" viewBox="0 0 48 36" role="img" aria-label="Mimosa">
            <g class="leaf-group">
              <path class="stem" d="M40 8 L8 28" />
              <g class="leaflets leaflets-top">
                <g class="leaflets-inner">
                  <ellipse class="leaflet" cx="10.2" cy="22.6" rx="6.0" ry="2.8" transform="rotate(-26 10.2 22.6)" />
                  <ellipse class="leaflet" cx="15.4" cy="19.6" rx="5.8" ry="2.7" transform="rotate(-26 15.4 19.6)" />
                  <ellipse class="leaflet" cx="20.6" cy="16.6" rx="5.4" ry="2.5" transform="rotate(-26 20.6 16.6)" />
                  <ellipse class="leaflet" cx="25.8" cy="13.6" rx="5.0" ry="2.3" transform="rotate(-26 25.8 13.6)" />
                  <ellipse class="leaflet" cx="31.0" cy="10.6" rx="4.6" ry="2.1" transform="rotate(-26 31.0 10.6)" />
                  <ellipse class="leaflet" cx="36.2" cy="7.6" rx="4.2" ry="2.0" transform="rotate(-26 36.2 7.6)" />
                </g>
              </g>
              <g class="leaflets leaflets-bottom">
                <g class="leaflets-inner">
                  <ellipse class="leaflet" cx="13.0" cy="26.8" rx="6.0" ry="2.8" transform="rotate(-26 13.0 26.8)" />
                  <ellipse class="leaflet" cx="18.2" cy="23.8" rx="5.8" ry="2.7" transform="rotate(-26 18.2 23.8)" />
                  <ellipse class="leaflet" cx="23.4" cy="20.8" rx="5.4" ry="2.5" transform="rotate(-26 23.4 20.8)" />
                  <ellipse class="leaflet" cx="28.6" cy="17.8" rx="5.0" ry="2.3" transform="rotate(-26 28.6 17.8)" />
                  <ellipse class="leaflet" cx="33.8" cy="14.8" rx="4.6" ry="2.1" transform="rotate(-26 33.8 14.8)" />
                  <ellipse class="leaflet" cx="39.0" cy="11.8" rx="4.2" ry="2.0" transform="rotate(-26 39.0 11.8)" />
                </g>
              </g>
            </g>
          </svg>
        </span>
        <span class="brand-text">
          Mimosa
          <span>Defense Core</span>
        </span>
      </button>
      {#if sidebarOpen}
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
      </nav>
      <div class="section">
        <div class="surface panel-sm">
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
      {/if}
    </aside>
    <main class="main">
      <slot />
    </main>
  </div>
{/if}
