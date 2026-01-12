<script lang="ts">
  export let title: string | null = null;
  export let subtitle: string | null = null;
</script>

<div class="surface" style="padding: 18px;">
  {#if title}
    <div style="font-weight: 600; margin-bottom: 4px;">{title}</div>
  {/if}
  {#if subtitle}
    <div style="color: var(--muted); font-size: 13px; margin-bottom: 12px;">
      {subtitle}
    </div>
  {/if}
  <slot />
</div>
