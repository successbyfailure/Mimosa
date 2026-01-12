let chartPromise: Promise<void> | null = null;

export const loadChartJs = (): Promise<void> => {
  if (typeof window === 'undefined') {
    return Promise.resolve();
  }
  if ((window as Window & { Chart?: unknown }).Chart) {
    return Promise.resolve();
  }
  if (chartPromise) {
    return chartPromise;
  }
  chartPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = '/static/chart.umd.min.js';
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('No se pudo cargar Chart.js'));
    document.head.appendChild(script);
  });
  return chartPromise;
};
