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

<div class="surface panel stat-card">
  <div class="card-head">
    <div class="stat-title">{title}</div>
    <span class="badge badge-muted" style="color: {trendColors[trend]};">{trend}</span>
  </div>
  <div class="stat-value">{value}</div>
  <div class="stat-subtitle">{subtitle}</div>
</div>
