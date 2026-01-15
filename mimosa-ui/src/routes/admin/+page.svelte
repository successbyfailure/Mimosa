<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';

  onMount(() => {
    goto('/settings?tab=firewall', { replaceState: true });
  });
</script>
