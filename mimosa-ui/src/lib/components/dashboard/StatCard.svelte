<script lang="ts">
  export let title: string;
  export let value: string | number;
  export let subtitle: string;
  export let trend: 'up' | 'down' | 'neutral' = 'neutral';

  const trendColors: Record<'up' | 'down' | 'neutral', string> = {
    up: 'var(--success)',
    down: 'var(--danger)',
    neutral: 'var(--muted)'
  };
</script>

<div class="surface" style="padding: 18px;">
  <div style="display: flex; justify-content: space-between; align-items: center;">
    <div style="font-size: 13px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--muted);">
      {title}
    </div>
    <span class="badge" style="background: rgba(148, 163, 184, 0.2); color: {trendColors[trend]};">
      {trend}
    </span>
  </div>
  <div style="font-size: 28px; font-weight: 600; margin-top: 14px;">{value}</div>
  <div style="color: var(--muted); font-size: 13px; margin-top: 6px;">{subtitle}</div>
</div>
