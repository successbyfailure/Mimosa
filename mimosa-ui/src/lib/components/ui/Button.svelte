<script lang="ts">
  export let variant: 'primary' | 'ghost' = 'primary';
  export let type: 'button' | 'submit' | 'reset' = 'button';
</script>

<button class={variant} type={type}>
  <slot />
</button>
