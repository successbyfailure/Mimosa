<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { loadChartJs } from '$lib/charts/chartLoader';

  export let labels: string[] = [];
  export let data: number[] = [];
  export let label = '';
  export let color = '#2dd4bf';
  export let colors: string[] | null = null;
  export let type: 'line' | 'bar' | 'doughnut' = 'line';
  export let showLegend = false;
  export let height = 220;

  let canvas: HTMLCanvasElement | null = null;
  let chart: any = null;

  const buildChart = async () => {
    if (!canvas) {
      return;
    }
    await loadChartJs();
    const Chart = (window as Window & { Chart: any }).Chart;
    if (!Chart) {
      return;
    }
    if (chart) {
      chart.destroy();
    }

    const palette = colors || ['#38bdf8', '#22c55e', '#fbbf24', '#f472b6', '#a78bfa', '#60a5fa'];
    const dataset = {
      label,
      data,
      borderColor: type === 'doughnut' ? '#0b1220' : color,
      backgroundColor:
        type === 'doughnut' ? data.map((_, idx) => palette[idx % palette.length]) : color + '33',
      borderWidth: type === 'doughnut' ? 1 : 2,
      pointRadius: type === 'line' ? 2 : 0,
      fill: type === 'line'
    };

    // Plugin para mostrar el total en el centro del donut
    const centerTextPlugin = {
      id: 'centerText',
      beforeDraw: (chart: any) => {
        if (type !== 'doughnut') {
          return;
        }
        const ctx = chart.ctx;
        const width = chart.width;
        const height = chart.height;
        const total = data.reduce((sum, val) => sum + val, 0);

        ctx.save();
        ctx.font = 'bold 32px Space Grotesk, sans-serif';
        ctx.fillStyle = '#f8fafc';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(total.toString(), width / 2, height / 2 - 10);

        ctx.font = '12px Space Grotesk, sans-serif';
        ctx.fillStyle = '#92a4bf';
        ctx.fillText('Total', width / 2, height / 2 + 18);
        ctx.restore();
      }
    };

    const options: Record<string, unknown> = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: showLegend || type === 'doughnut',
          labels: {
            color: '#e2e8f0'
          }
        }
      }
    };

    if (type !== 'doughnut') {
      options.scales = {
        x: {
          grid: {
            color: 'rgba(148, 163, 184, 0.1)'
          },
          ticks: {
            color: '#94a3b8',
            maxTicksLimit: 6
          }
        },
        y: {
          grid: {
            color: 'rgba(148, 163, 184, 0.1)'
          },
          ticks: {
            color: '#94a3b8'
          }
        }
      };
    }

    chart = new Chart(canvas, {
      type,
      data: {
        labels,
        datasets: [dataset]
      },
      options,
      plugins: type === 'doughnut' ? [centerTextPlugin] : []
    });
  };

  const updateChart = () => {
    if (!chart) {
      return;
    }
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    if (type === 'doughnut') {
      const palette = colors || ['#38bdf8', '#22c55e', '#fbbf24', '#f472b6', '#a78bfa', '#60a5fa'];
      chart.data.datasets[0].backgroundColor = data.map((_, idx) => palette[idx % palette.length]);
    }
    chart.update();
  };

  $: if (chart) {
    updateChart();
  }

  onMount(() => {
    buildChart();
  });

  onDestroy(() => {
    if (chart) {
      chart.destroy();
    }
  });
</script>

<div style={`height: ${height}px;`}>
  <canvas bind:this={canvas}></canvas>
</div>
