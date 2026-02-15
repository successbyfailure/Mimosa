<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth';

  type ProxyTrapPolicy = {
    pattern: string;
    severity: string;
  };

  type ProxyTrapConfig = {
    enabled: boolean;
    port: number;
    default_severity: string;
    response_type: 'silence' | '404' | 'custom';
    custom_html?: string | null;
    trap_hosts: string[];
    domain_policies: ProxyTrapPolicy[];
  };

  type PortDetectorRule = {
    protocol: 'tcp' | 'udp';
    severity: string;
    description?: string | null;
    port?: number | null;
    ports?: number[] | null;
    start?: number | null;
    end?: number | null;
  };

  type PortDetectorConfig = {
    enabled: boolean;
    default_severity: string;
    rules: PortDetectorRule[];
  };

  type MimosaNpmRule = {
    host: string;
    path: string;
    status: string;
    severity: string;
  };

  type MimosaNpmIgnoreRule = {
    host: string;
    path: string;
    status: string;
  };

  type MimosaNpmConfig = {
    enabled: boolean;
    default_severity: string;
    fallback_severity?: string | null;
    shared_secret?: string | null;
    rules: MimosaNpmRule[];
    ignore_list: MimosaNpmIgnoreRule[];
    alert_fallback: boolean;
    alert_unregistered_domain: boolean;
    alert_suspicious_path: boolean;
  };

  type PluginEntry = {
    name: string;
    enabled: boolean;
    config: Record<string, any>;
  };

  type PortAliasResponse = {
    ports_aliases: Record<string, string> | string[];
    port_entries: Record<string, number[]>;
    synced?: Record<string, number[]>;
  };

  type MimosaEvent = {
    id: number;
    host?: string | null;
    path?: string | null;
    severity?: string | null;
    created_at: string;
    description_clean?: string | null;
    context?: Record<string, any> | null;
  };

  type MimosaNpmStats = {
    total: number;
    sample: number;
    top_domains: { domain: string; count: number }[];
    top_paths: { path: string; count: number }[];
    top_status_codes: { status: string; count: number }[];
  };

  const defaultProxyPolicies: ProxyTrapPolicy[] = [
    { pattern: 'phpmyadmin.*', severity: 'alto' },
    { pattern: 'admin.*', severity: 'alto' },
    { pattern: '*.admin', severity: 'alto' },
    { pattern: 'cpanel.*', severity: 'alto' }
  ];

  const defaultPortDetectorRules: PortDetectorRule[] = [
    {
      protocol: 'tcp',
      severity: 'alto',
      description: 'RemoteAccess',
      ports: [2200, 2222, 3389, 5900, 5901, 5902, 5903, 5938, 6080, 7070, 8200, 12975]
    },
    {
      protocol: 'udp',
      severity: 'medio',
      description: '-',
      ports: [53, 123]
    },
    {
      protocol: 'tcp',
      severity: 'alto',
      description: 'databases',
      ports: [1521, 1433, 3306, 5432, 27017, 6379, 9200, 9042]
    },
    {
      protocol: 'tcp',
      severity: 'alto',
      description: 'Infra',
      ports: [21, 23, 389, 445, 636, 631]
    },
    {
      protocol: 'tcp',
      severity: 'alto',
      description: 'HTTP-dev',
      ports: [8000, 8001, 8080, 8443, 5000, 3000]
    },
    {
      protocol: 'tcp',
      severity: 'alto',
      description: 'email',
      ports: [25, 110, 143, 465, 587, 993, 995]
    }
  ];

  const defaultMimosaNpmRules: MimosaNpmRule[] = [
    { host: '*', path: '/xmlrpc.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/wp-content/plugins/hellopress/wp_filemanager.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/.git/*', status: '*', severity: 'alto' },
    { host: '*', path: '/cgi-bin/*', status: '*', severity: 'alto' },
    { host: '*', path: '/admin/function.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/ioxi-o.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/vx.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/as.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/class-t.api.php*', status: '*', severity: 'alto' },
    { host: '*', path: '/wp-admin/*', status: '*', severity: 'medio' },
    { host: '*', path: '/wp-login.php*', status: '*', severity: 'medio' },
    { host: 'desconocido', path: '*', status: '*', severity: 'alto' }
  ];

  let loading = false;
  let error: string | null = null;

  let proxyConfig: ProxyTrapConfig | null = null;
  let proxyMessage: string | null = null;
  let proxyError: string | null = null;
  let proxyHostsText = '';
  let proxyPolicyPattern = '';
  let proxyPolicySeverity = 'alto';

  let portConfig: PortDetectorConfig | null = null;
  let portMessage: string | null = null;
  let portError: string | null = null;
  let portRuleProtocol: 'tcp' | 'udp' = 'tcp';
  let portRuleSeverity = 'medio';
  let portRulePorts = '';
  let portRuleStart = '';
  let portRuleEnd = '';
  let portRuleDescription = '';
  let portEditIndex: number | null = null;
  let portAlias: PortAliasResponse | null = null;
  let portAliasMessage: string | null = null;

  let mimosaConfig: MimosaNpmConfig | null = null;
  let mimosaMessage: string | null = null;
  let mimosaError: string | null = null;
  let mimosaRuleForm: MimosaNpmRule = {
    host: '*',
    path: '*',
    status: '*',
    severity: 'medio'
  };
  let mimosaRuleEditIndex: number | null = null;
  let mimosaFallbackSeverity = '';
  let mimosaIgnoreForm: MimosaNpmIgnoreRule = {
    host: '*',
    path: '*',
    status: '*'
  };
  let mimosaEvents: MimosaEvent[] = [];
  let mimosaStats: MimosaNpmStats | null = null;
  let mimosaStatsMessage: string | null = null;
  let mimosaEndpoint = '';
  let activeTab: 'proxytrap' | 'portdetector' | 'mimosanpm' = 'proxytrap';

  const requestJson = async <T>(path: string, options?: RequestInit): Promise<T> => {
    const response = await fetch(path, {
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {})
      },
      credentials: 'include',
      ...options
    });

    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      let detail = payload?.detail;
      let message = 'Error en la solicitud';
      if (detail) {
        if (typeof detail === 'string') {
          message = detail;
        } else if (detail?.message && typeof detail.message === 'string') {
          message = detail.message;
        } else {
          try {
            message = JSON.stringify(detail);
          } catch {
            message = String(detail);
          }
        }
      }
      const error = new Error(message);
      (error as Error & { payload?: unknown }).payload = payload;
      throw error;
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json() as Promise<T>;
  };

  const loadPlugins = async () => {
    loading = true;
    error = null;
    try {
      const plugins = await requestJson<PluginEntry[]>('/api/plugins');
      const proxy = plugins.find((item) => item.name === 'proxytrap');
      const port = plugins.find((item) => item.name === 'portdetector');
      const mimosa = plugins.find((item) => item.name === 'mimosanpm');

      if (proxy?.config) {
        const normalized = {
          ...proxy.config,
          trap_hosts: proxy.config.trap_hosts || [],
          domain_policies: proxy.config.domain_policies || []
        } as ProxyTrapConfig;
        proxyConfig = normalized;
        proxyHostsText = normalized.trap_hosts.join(', ');
      }
      if (port?.config) {
        portConfig = {
          ...port.config,
          rules: port.config.rules || []
        } as PortDetectorConfig;
      }
      if (mimosa?.config) {
        mimosaConfig = {
          ...mimosa.config,
          rules: mimosa.config.rules || [],
          ignore_list: mimosa.config.ignore_list || []
        } as MimosaNpmConfig;
        mimosaFallbackSeverity = mimosaConfig.fallback_severity || '';
      }
    } catch (err) {
      error = err instanceof Error ? err.message : 'No se pudo cargar plugins';
    } finally {
      loading = false;
    }
  };

  const saveProxytrap = async () => {
    if (!proxyConfig) {
      return;
    }
    proxyMessage = null;
    proxyError = null;
    try {
      const payload: ProxyTrapConfig = {
        enabled: proxyConfig.enabled,
        port: Number(proxyConfig.port) || 8081,
        default_severity: proxyConfig.default_severity,
        response_type: proxyConfig.response_type,
        custom_html: proxyConfig.response_type === 'custom' ? proxyConfig.custom_html || '' : null,
        trap_hosts: proxyHostsText
          .split(',')
          .map((entry) => entry.trim())
          .filter(Boolean),
        domain_policies: proxyConfig.domain_policies || []
      };
      proxyConfig = (await requestJson<ProxyTrapConfig>('/api/plugins/proxytrap', {
        method: 'PUT',
        body: JSON.stringify(payload)
      })) as ProxyTrapConfig;
      proxyMessage = 'ProxyTrap actualizado';
    } catch (err) {
      proxyError = err instanceof Error ? err.message : 'No se pudo guardar ProxyTrap';
    }
  };

  const addProxyPolicy = () => {
    if (!proxyConfig) {
      return;
    }
    const pattern = proxyPolicyPattern.trim();
    if (!pattern) {
      proxyError = 'El patron es obligatorio';
      return;
    }
    proxyConfig.domain_policies = [
      ...(proxyConfig.domain_policies || []),
      { pattern, severity: proxyPolicySeverity }
    ];
    proxyPolicyPattern = '';
  };

  const removeProxyPolicy = (index: number) => {
    if (!proxyConfig) {
      return;
    }
    proxyConfig.domain_policies = proxyConfig.domain_policies.filter((_, idx) => idx !== index);
  };

  const resetProxyPolicies = () => {
    if (!proxyConfig) {
      return;
    }
    proxyConfig.domain_policies = defaultProxyPolicies.map((item) => ({ ...item }));
  };

  const formatPortRule = (rule: PortDetectorRule) => {
    if (rule.port) {
      return String(rule.port);
    }
    if (rule.start && rule.end) {
      return `${rule.start}-${rule.end}`;
    }
    if (rule.ports && rule.ports.length) {
      return rule.ports.join(', ');
    }
    return '-';
  };

  const resetPortRuleForm = () => {
    portRuleProtocol = 'tcp';
    portRuleSeverity = 'medio';
    portRulePorts = '';
    portRuleStart = '';
    portRuleEnd = '';
    portRuleDescription = '';
    portEditIndex = null;
  };

  const addPortDetectorDefaults = () => {
    if (!portConfig) {
      return;
    }
    portConfig.rules = defaultPortDetectorRules.map((rule) => ({
      ...rule,
      ports: rule.ports ? [...rule.ports] : []
    }));
    resetPortRuleForm();
    portMessage = 'Reglas por defecto añadidas';
    portError = null;
  };

  const startEditPortRule = (rule: PortDetectorRule, index: number) => {
    portEditIndex = index;
    portRuleProtocol = rule.protocol;
    portRuleSeverity = rule.severity;
    portRulePorts = rule.ports?.length ? rule.ports.join(', ') : '';
    portRuleDescription = rule.description || '';
    if (!rule.ports?.length && rule.start && rule.end) {
      portRuleStart = String(rule.start);
      portRuleEnd = String(rule.end);
    } else {
      portRuleStart = '';
      portRuleEnd = '';
    }
  };

  const addPortRule = () => {
    if (!portConfig) {
      return;
    }
    portError = null;
    const ports = portRulePorts
      .split(/[\s,]+/)
      .map((entry) => Number(entry))
      .filter((value) => Number.isFinite(value) && value > 0);
    const start = portRuleStart ? Number(portRuleStart) : null;
    const end = portRuleEnd ? Number(portRuleEnd) : null;

    if (!ports.length && !(start && end)) {
      portError = 'Indica puertos o rango';
      return;
    }

    const rule: PortDetectorRule = {
      protocol: portRuleProtocol,
      severity: portRuleSeverity,
      description: portRuleDescription?.trim() || null
    };
    if (ports.length) {
      rule.ports = ports;
    }
    if (start && end) {
      rule.start = start;
      rule.end = end;
    }

    if (portEditIndex != null) {
      const nextRules = [...(portConfig.rules || [])];
      nextRules[portEditIndex] = rule;
      portConfig.rules = nextRules;
    } else {
      portConfig.rules = [...(portConfig.rules || []), rule];
    }
    resetPortRuleForm();
  };

  const removePortRule = (index: number) => {
    if (!portConfig) {
      return;
    }
    portConfig.rules = portConfig.rules.filter((_, idx) => idx !== index);
    if (portEditIndex != null) {
      resetPortRuleForm();
    }
  };

  const savePortDetector = async () => {
    if (!portConfig) {
      return;
    }
    portMessage = null;
    portError = null;
    try {
      const payload: PortDetectorConfig = {
        enabled: portConfig.enabled,
        default_severity: portConfig.default_severity,
        rules: portConfig.rules || []
      };
      portConfig = await requestJson<PortDetectorConfig>('/api/plugins/portdetector', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      portMessage = 'Port Detector actualizado';
    } catch (err) {
      if (err instanceof Error) {
        const payload = (err as Error & { payload?: any }).payload;
        if (payload?.detail?.failed_ports?.length) {
          const ports = payload.detail.failed_ports
            .map((entry: { protocol?: string; port?: number; message?: string }) => {
              const portLabel = `${entry.protocol ?? '?'}:${entry.port ?? '?'}`;
              const detail = entry.message ? ` (${entry.message})` : '';
              return `${portLabel}${detail}`;
            })
            .join(', ');
          portError = `${err.message}${ports ? ` (puertos con error: ${ports})` : ''}`;
        } else {
          portError = err.message;
        }
      } else {
        try {
          portError = typeof err === 'string' ? err : JSON.stringify(err);
        } catch {
          portError = 'No se pudo guardar Port Detector';
        }
      }
    }
  };

  const loadPortAliases = async () => {
    portAliasMessage = null;
    try {
      portAlias = await requestJson<PortAliasResponse>('/api/plugins/portdetector/aliases');
      portAliasMessage = 'Alias cargados';
    } catch (err) {
      portAliasMessage = err instanceof Error ? err.message : 'No se pudieron cargar los alias';
    }
  };

  const syncPortAliases = async () => {
    portAliasMessage = null;
    try {
      portAlias = await requestJson<PortAliasResponse>('/api/plugins/portdetector/aliases/sync', {
        method: 'POST'
      });
      portAliasMessage = 'Alias sincronizados';
    } catch (err) {
      portAliasMessage = err instanceof Error ? err.message : 'No se pudo sincronizar alias';
    }
  };

  const saveMimosaNpm = async (rotateSecret = false) => {
    if (!mimosaConfig) {
      return;
    }
    mimosaMessage = null;
    mimosaError = null;
    try {
      const payload = {
        enabled: mimosaConfig.enabled,
        default_severity: mimosaConfig.default_severity,
        fallback_severity: mimosaFallbackSeverity || null,
        shared_secret: mimosaConfig.shared_secret || null,
        rotate_secret: rotateSecret,
        rules: mimosaConfig.rules || [],
        ignore_list: mimosaConfig.ignore_list || [],
        alert_fallback: mimosaConfig.alert_fallback,
        alert_unregistered_domain: mimosaConfig.alert_unregistered_domain,
        alert_suspicious_path: mimosaConfig.alert_suspicious_path
      };
      mimosaConfig = await requestJson<MimosaNpmConfig>('/api/plugins/mimosanpm', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      mimosaFallbackSeverity = mimosaConfig.fallback_severity || '';
      mimosaMessage = rotateSecret ? 'Secreto rotado' : 'MimosaNPM actualizado';
    } catch (err) {
      mimosaError = err instanceof Error ? err.message : 'No se pudo guardar MimosaNPM';
    }
  };

  const addMimosaRule = () => {
    if (!mimosaConfig) {
      return;
    }
    if (mimosaRuleEditIndex !== null) {
      const nextRules = [...(mimosaConfig.rules || [])];
      nextRules[mimosaRuleEditIndex] = { ...mimosaRuleForm };
      mimosaConfig.rules = nextRules;
      mimosaRuleEditIndex = null;
    } else {
      mimosaConfig.rules = [...(mimosaConfig.rules || []), { ...mimosaRuleForm }];
    }
    mimosaRuleForm = { host: '*', path: '*', status: '*', severity: 'medio' };
  };

  const editMimosaRule = (index: number) => {
    if (!mimosaConfig) {
      return;
    }
    const rule = mimosaConfig.rules[index];
    if (!rule) {
      return;
    }
    mimosaRuleEditIndex = index;
    mimosaRuleForm = { ...rule };
  };

  const cancelMimosaRuleEdit = () => {
    mimosaRuleEditIndex = null;
    mimosaRuleForm = { host: '*', path: '*', status: '*', severity: 'medio' };
  };

  const removeMimosaRule = (index: number) => {
    if (!mimosaConfig) {
      return;
    }
    mimosaConfig.rules = mimosaConfig.rules.filter((_, idx) => idx !== index);
    if (mimosaRuleEditIndex === index) {
      cancelMimosaRuleEdit();
    } else if (mimosaRuleEditIndex !== null && index < mimosaRuleEditIndex) {
      mimosaRuleEditIndex -= 1;
    }
  };

  const addMimosaIgnore = () => {
    if (!mimosaConfig) {
      return;
    }
    mimosaConfig.ignore_list = [...(mimosaConfig.ignore_list || []), { ...mimosaIgnoreForm }];
    mimosaIgnoreForm = { host: '*', path: '*', status: '*' };
  };

  const removeMimosaIgnore = (index: number) => {
    if (!mimosaConfig) {
      return;
    }
    mimosaConfig.ignore_list = mimosaConfig.ignore_list.filter((_, idx) => idx !== index);
  };

  const addMimosaDefaults = () => {
    if (!mimosaConfig) {
      return;
    }
    mimosaConfig.rules = defaultMimosaNpmRules.map((rule) => ({ ...rule }));
    mimosaConfig.ignore_list = [];
    mimosaConfig.default_severity = 'alto';
    mimosaFallbackSeverity = '';
    mimosaConfig.alert_fallback = true;
    mimosaConfig.alert_unregistered_domain = true;
    mimosaConfig.alert_suspicious_path = true;
    mimosaMessage = 'Defaults aplicados';
    mimosaError = null;
  };

  const loadMimosaEvents = async () => {
    try {
      mimosaEvents = await requestJson<MimosaEvent[]>('/api/plugins/mimosanpm/events?limit=80');
    } catch (err) {
      // opcional
    }
  };

  const loadMimosaStats = async () => {
    mimosaStatsMessage = null;
    try {
      mimosaStats = await requestJson<MimosaNpmStats>(
        '/api/plugins/mimosanpm/stats?limit=6&sample=500'
      );
      mimosaStatsMessage = `Analizando ${mimosaStats.total} eventos recientes.`;
    } catch (err) {
      mimosaStats = null;
      mimosaStatsMessage = err instanceof Error ? err.message : 'No se pudieron cargar stats';
    }
  };

  const applyEventToRule = (event: MimosaEvent) => {
    const statusCode = event.context?.status_code;
    mimosaRuleEditIndex = null;
    mimosaRuleForm = {
      host: event.host || '*',
      path: event.path || '*',
      status: statusCode ? String(statusCode) : '*',
      severity: event.severity || 'medio'
    };
  };

  const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const matchesPattern = (pattern: string, value: string, ignoreCase = false) => {
    const normalized = (pattern || '*').trim();
    if (!normalized || normalized === '*') {
      return true;
    }
    const flags = ignoreCase ? 'i' : '';
    const regex = new RegExp(
      '^' + escapeRegex(normalized).replace(/\\\*/g, '.*').replace(/\\\?/g, '.') + '$',
      flags
    );
    return regex.test(value || '');
  };

  const matchesMimosaRule = (rule: MimosaNpmRule, event: MimosaEvent) => {
    const host = event.host || '';
    const path = event.path || '/';
    const statusValue =
      event.context?.status_code !== undefined && event.context?.status_code !== null
        ? String(event.context.status_code)
        : 'n/a';
    return (
      matchesPattern(rule.host, host, true) &&
      matchesPattern(rule.path, path) &&
      matchesPattern(rule.status, statusValue)
    );
  };

  const eventCovered = (event: MimosaEvent) => {
    if (!mimosaConfig) {
      return false;
    }
    return (mimosaConfig.rules || []).some((rule) => matchesMimosaRule(rule, event));
  };

  const formatDate = (value: string) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  };

  const setPluginTab = (tab: 'proxytrap' | 'portdetector' | 'mimosanpm') => {
    activeTab = tab;
    if (tab === 'mimosanpm') {
      loadMimosaEvents();
      loadMimosaStats();
    }
  };

  $: if (!$authStore.loading && !$authStore.user) {
    goto('/login');
  }

  onMount(() => {
    loadPlugins();
    loadMimosaEvents();
    if (typeof window !== 'undefined') {
      mimosaEndpoint = `${window.location.origin}/api/plugins/mimosanpm/ingest`;
    }
  });
</script>

<section class="page-header">
  <div class="badge">Plugins</div>
  <h1>Gestion de plugins</h1>
  <p>Activa y configura ProxyTrap, Port Detector y MimosaNPM.</p>
</section>

{#if error}
  <div class="surface panel-sm" style="border-color: rgba(248, 113, 113, 0.5);">
    <strong>Error</strong>
    <div style="color: var(--muted); margin-top: 4px;">{error}</div>
  </div>
{/if}

<div class="plugin-tabs">
  <button
    class="plugin-tab {activeTab === 'proxytrap' ? 'active' : ''}"
    on:click={() => setPluginTab('proxytrap')}
  >
    ProxyTrap
  </button>
  <button
    class="plugin-tab {activeTab === 'portdetector' ? 'active' : ''}"
    on:click={() => setPluginTab('portdetector')}
  >
    Port Detector
  </button>
  <button
    class="plugin-tab {activeTab === 'mimosanpm' ? 'active' : ''}"
    on:click={() => setPluginTab('mimosanpm')}
  >
    MimosaNPM
  </button>
</div>

<div class="section">
  {#if activeTab === 'proxytrap'}
  <div class="surface panel">
    <div class="card-head">
      <div>
        <div class="badge">ProxyTrap</div>
        <h3 class="card-title" style="margin-top: 12px;">Servidor honeypot</h3>
      </div>
      <button class="secondary" on:click={loadPlugins}>Recargar</button>
    </div>

    {#if !proxyConfig}
      <div style="margin-top: 12px;">Cargando configuracion...</div>
    {:else}
      <div class="form-grid" style="margin-top: 12px;">
        <label class="check-item">
          <input type="checkbox" bind:checked={proxyConfig.enabled} />
          <span>Habilitar ProxyTrap</span>
        </label>
        <div class="form-row">
          <label>
            <div class="field-label">Puerto</div>
            <input type="number" min="1" bind:value={proxyConfig.port} />
          </label>
          <label>
            <div class="field-label">Severidad</div>
            <select bind:value={proxyConfig.default_severity}>
              <option value="bajo">Bajo</option>
              <option value="medio">Medio</option>
              <option value="alto">Alto</option>
            </select>
          </label>
        </div>
        <div class="form-row">
          <label>
            <div class="field-label">Respuesta</div>
            <select bind:value={proxyConfig.response_type}>
              <option value="silence">Silencio (204)</option>
              <option value="404">404</option>
              <option value="custom">HTML personalizado</option>
            </select>
          </label>
          <label>
            <div class="field-label">Trap hosts (coma)</div>
            <input bind:value={proxyHostsText} placeholder="admin.ejemplo.com, intranet.local" />
          </label>
        </div>
        {#if proxyConfig.response_type === 'custom'}
          <label>
            <div class="field-label">HTML</div>
            <textarea rows="4" bind:value={proxyConfig.custom_html} placeholder="<h1>No permitido</h1>"></textarea>
          </label>
        {/if}
      </div>

      <div style="margin-top: 16px;">
        <div class="badge">Severidad por dominio</div>
        <div class="form-grid" style="margin-top: 10px;">
          <div class="form-row">
            <label>
              <div class="field-label">Patron</div>
              <input bind:value={proxyPolicyPattern} placeholder="*.admin o cpanel.*" />
            </label>
            <label>
              <div class="field-label">Severidad</div>
              <select bind:value={proxyPolicySeverity}>
                <option value="bajo">Bajo</option>
                <option value="medio">Medio</option>
                <option value="alto">Alto</option>
              </select>
            </label>
          </div>
          <div class="action-row">
            <button class="secondary" on:click={addProxyPolicy}>Agregar</button>
            <button class="ghost" on:click={resetProxyPolicies}>Defaults</button>
          </div>
        </div>
        <div style="margin-top: 12px; overflow-x: auto;">
          <table class="table table-responsive">
            <thead>
              <tr>
                <th>Patron</th>
                <th>Severidad</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#if proxyConfig.domain_policies.length === 0}
                <tr><td colspan="3">Sin reglas.</td></tr>
              {:else}
                {#each proxyConfig.domain_policies as policy, index}
                  <tr>
                    <td data-label="Patron">{policy.pattern}</td>
                    <td data-label="Severidad">{policy.severity}</td>
                    <td data-label="Accion">
                      <button class="ghost" on:click={() => removeProxyPolicy(index)}>
                        Quitar
                      </button>
                    </td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
        </div>
      </div>

      {#if proxyMessage}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">{proxyMessage}</div>
      {/if}
      {#if proxyError}
        <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">{proxyError}</div>
      {/if}
      <div style="margin-top: 14px;">
        <button class="primary" on:click={saveProxytrap}>Guardar ProxyTrap</button>
      </div>
    {/if}
  </div>
  {/if}

  {#if activeTab === 'portdetector'}
  <div class="surface panel">
    <div class="card-head">
      <div>
        <div class="badge">Port Detector</div>
        <h3 class="card-title" style="margin-top: 12px;">Escucha de puertos</h3>
      </div>
      <button class="secondary" on:click={loadPlugins}>Recargar</button>
    </div>

    {#if !portConfig}
      <div style="margin-top: 12px;">Cargando configuracion...</div>
    {:else}
      <div class="form-grid" style="margin-top: 12px;">
        <label class="check-item">
          <input type="checkbox" bind:checked={portConfig.enabled} />
          <span>Habilitar Port Detector</span>
        </label>
        <label>
          <div class="field-label">Severidad</div>
          <select bind:value={portConfig.default_severity}>
            <option value="bajo">Bajo</option>
            <option value="medio">Medio</option>
            <option value="alto">Alto</option>
          </select>
        </label>
      </div>

      <div style="margin-top: 16px;">
        <div class="card-head">
          <div class="badge">Reglas</div>
          <button class="ghost" on:click={addPortDetectorDefaults}>Añadir defaults</button>
        </div>
        <div class="form-grid" style="margin-top: 10px;">
          <div class="form-row">
            <label>
              <div class="field-label">Protocolo</div>
              <select bind:value={portRuleProtocol}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </label>
            <label>
              <div class="field-label">Severidad</div>
              <select bind:value={portRuleSeverity}>
                <option value="bajo">Bajo</option>
                <option value="medio">Medio</option>
                <option value="alto">Alto</option>
              </select>
            </label>
          </div>
          <label>
            <div class="field-label">Puertos (coma)</div>
            <input bind:value={portRulePorts} placeholder="22, 80, 443" />
          </label>
          <label>
            <div class="field-label">Descripcion</div>
            <input bind:value={portRuleDescription} placeholder="Ej: SSH expuesto" />
          </label>
          <div class="form-row">
            <label>
              <div class="field-label">Inicio rango</div>
              <input type="number" min="1" bind:value={portRuleStart} placeholder="1000" />
            </label>
            <label>
              <div class="field-label">Fin rango</div>
              <input type="number" min="1" bind:value={portRuleEnd} placeholder="2000" />
            </label>
          </div>
          <div class="card-actions">
            <button class="secondary" on:click={addPortRule}>
              {portEditIndex != null ? 'Guardar cambios' : 'Agregar regla'}
            </button>
            {#if portEditIndex != null}
              <button class="ghost" on:click={resetPortRuleForm}>Cancelar</button>
            {/if}
          </div>
        </div>
        {#if portError}
          <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">{portError}</div>
        {/if}
        <div style="margin-top: 12px; overflow-x: auto;">
          <table class="table table-responsive">
          <thead>
            <tr>
              <th>Protocolo</th>
              <th>Detalle</th>
              <th>Descripcion</th>
              <th>Severidad</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#if portConfig.rules.length === 0}
              <tr><td colspan="5">Sin reglas.</td></tr>
            {:else}
              {#each portConfig.rules as rule, index}
                <tr>
                  <td data-label="Protocolo">{rule.protocol}</td>
                  <td data-label="Detalle">{formatPortRule(rule)}</td>
                  <td data-label="Descripcion">{rule.description || '-'}</td>
                  <td data-label="Severidad">{rule.severity}</td>
                  <td data-label="Accion">
                    <button class="secondary btn-sm" on:click={() => startEditPortRule(rule, index)}>
                      Editar
                      </button>
                      <button class="ghost" on:click={() => removePortRule(index)}>
                        Quitar
                      </button>
                    </td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
        </div>
      </div>

      <div style="margin-top: 16px;">
        <div class="badge">Alias</div>
        <div class="action-row" style="margin-top: 10px;">
          <button class="secondary" on:click={loadPortAliases}>Ver alias</button>
          <button class="ghost" on:click={syncPortAliases}>Sincronizar alias</button>
        </div>
        {#if portAliasMessage}
          <div style="margin-top: 8px; color: var(--muted); font-size: 12px;">{portAliasMessage}</div>
        {/if}
        <div style="margin-top: 12px; overflow-x: auto;">
          <table class="table table-responsive">
            <thead>
              <tr>
                <th>Protocolo</th>
                <th>Alias</th>
                <th>Puertos</th>
              </tr>
            </thead>
            <tbody>
              {#if !portAlias}
                <tr><td colspan="3">Sin datos.</td></tr>
              {:else}
                {#each Object.entries(portAlias.port_entries || {}) as entry}
                  <tr>
                    <td data-label="Protocolo">{entry[0].toUpperCase()}</td>
                    <td data-label="Alias">
                      {#if Array.isArray(portAlias.ports_aliases)}
                        -
                      {:else}
                        {portAlias.ports_aliases[entry[0]] || '-'}
                      {/if}
                    </td>
                    <td data-label="Puertos">{entry[1].join(', ') || '-'}</td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
        </div>
      </div>

      {#if portMessage}
        <div style="margin-top: 10px; color: var(--success); font-size: 13px;">{portMessage}</div>
      {/if}
      {#if portError}
        <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">{portError}</div>
      {/if}
      <div style="margin-top: 14px;">
        <button class="primary" on:click={savePortDetector}>Guardar Port Detector</button>
      </div>
    {/if}
  </div>
  {/if}

  {#if activeTab === 'mimosanpm'}
  <div class="surface panel">
    <div class="card-head">
      <div>
        <div class="badge">MimosaNPM</div>
        <h3 class="card-title" style="margin-top: 12px;">Agente para NPM</h3>
      </div>
      <div class="card-actions">
        <button
          class="secondary"
          on:click={() => {
            loadPlugins();
            loadMimosaEvents();
            loadMimosaStats();
          }}
        >
          Recargar
        </button>
        <button
          class="primary"
          type="button"
          disabled={!mimosaConfig}
          on:click={() => saveMimosaNpm(false)}
        >
          Guardar
        </button>
      </div>
    </div>

    {#if !mimosaConfig}
      <div style="margin-top: 12px;">Cargando configuracion...</div>
    {/if}
    {#if mimosaMessage}
      <div style="margin-top: 10px; color: var(--success); font-size: 13px;">{mimosaMessage}</div>
    {/if}
    {#if mimosaError}
      <div style="margin-top: 10px; color: var(--danger); font-size: 13px;">{mimosaError}</div>
    {/if}
  </div>

  {#if mimosaConfig}
  <div class="section" style="margin-top: 16px;">
    <div class="surface panel">
      <div class="badge">Configuracion</div>
      <h3 class="card-title" style="margin-top: 12px;">Agente y alertas</h3>
      <div class="form-grid" style="margin-top: 12px;">
        <label class="check-item">
          <input type="checkbox" bind:checked={mimosaConfig.enabled} />
          <span>Habilitar MimosaNPM</span>
        </label>
        <div class="form-row">
          <label>
            <div class="field-label">Severidad por defecto</div>
            <select bind:value={mimosaConfig.default_severity}>
              <option value="bajo">Bajo</option>
              <option value="medio">Medio</option>
              <option value="alto">Alto</option>
            </select>
          </label>
          <label>
            <div class="field-label">Severidad fallback</div>
            <select bind:value={mimosaFallbackSeverity}>
              <option value="">Auto (por defecto)</option>
              <option value="bajo">Bajo</option>
              <option value="medio">Medio</option>
              <option value="alto">Alto</option>
            </select>
          </label>
        </div>
        <div class="form-row">
          <label>
            <div class="field-label">Endpoint</div>
            <input readonly value={mimosaEndpoint} />
          </label>
          <label>
            <div class="field-label">Secreto</div>
            <div class="action-row">
              <input bind:value={mimosaConfig.shared_secret} />
              <button class="ghost" on:click={() => saveMimosaNpm(true)}>Rotar</button>
            </div>
          </label>
        </div>
        <div>
          <div class="field-label">Alertas</div>
          <div class="check-grid" style="margin-top: 6px;">
            <label class="check-item">
              <input type="checkbox" bind:checked={mimosaConfig.alert_fallback} />
              <span>Alertas fallback</span>
            </label>
            <label class="check-item">
              <input type="checkbox" bind:checked={mimosaConfig.alert_unregistered_domain} />
              <span>Dominios sin registrar</span>
            </label>
            <label class="check-item">
              <input type="checkbox" bind:checked={mimosaConfig.alert_suspicious_path} />
              <span>Rutas sospechosas</span>
            </label>
          </div>
        </div>
      </div>
    </div>

    <div class="surface panel">
      <div class="card-head">
        <div>
          <div class="badge">Reglas severidad</div>
          <h3 class="card-title" style="margin-top: 12px;">Reglas de matching</h3>
        </div>
        <button class="ghost" on:click={addMimosaDefaults}>Cargar defaults recomendados</button>
      </div>
      <div class="form-grid" style="margin-top: 10px;">
        <div class="form-row">
          <label>
            <div class="field-label">Host</div>
            <input bind:value={mimosaRuleForm.host} />
          </label>
          <label>
            <div class="field-label">Path</div>
            <input bind:value={mimosaRuleForm.path} />
          </label>
        </div>
        <div class="form-row">
          <label>
            <div class="field-label">Status</div>
            <input bind:value={mimosaRuleForm.status} />
          </label>
          <label>
            <div class="field-label">Severidad</div>
            <select bind:value={mimosaRuleForm.severity}>
              <option value="bajo">Bajo</option>
              <option value="medio">Medio</option>
              <option value="alto">Alto</option>
            </select>
          </label>
        </div>
        <div class="action-row">
          <button class="secondary" on:click={addMimosaRule}>
            {mimosaRuleEditIndex !== null ? 'Guardar regla' : 'Agregar regla'}
          </button>
          {#if mimosaRuleEditIndex !== null}
            <button class="ghost" on:click={cancelMimosaRuleEdit}>Cancelar</button>
          {/if}
        </div>
      </div>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th class="cell-nowrap">Host</th>
              <th>Path</th>
              <th class="cell-nowrap">Status</th>
              <th class="cell-nowrap">Severidad</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#if mimosaConfig.rules.length === 0}
              <tr><td colspan="5">Sin reglas.</td></tr>
            {:else}
              {#each mimosaConfig.rules as rule, index}
                <tr>
                  <td class="cell-nowrap" data-label="Host">{rule.host}</td>
                  <td class="cell-truncate" title={rule.path} data-label="Path">{rule.path}</td>
                  <td class="cell-nowrap" data-label="Status">{rule.status}</td>
                  <td class="cell-nowrap" data-label="Severidad">{rule.severity}</td>
                  <td data-label="Accion">
                    <div class="action-row">
                      <button class="ghost" on:click={() => editMimosaRule(index)}>Editar</button>
                      <button class="ghost" on:click={() => removeMimosaRule(index)}>Quitar</button>
                    </div>
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>

    <div class="surface panel">
      <div class="badge">Ignore list</div>
      <h3 class="card-title" style="margin-top: 12px;">Reglas de ignore</h3>
      <div class="form-grid" style="margin-top: 10px;">
        <div class="form-row">
          <label>
            <div class="field-label">Host</div>
            <input bind:value={mimosaIgnoreForm.host} />
          </label>
          <label>
            <div class="field-label">Path</div>
            <input bind:value={mimosaIgnoreForm.path} />
          </label>
        </div>
        <label>
          <div class="field-label">Status</div>
          <input bind:value={mimosaIgnoreForm.status} />
        </label>
        <button class="secondary" on:click={addMimosaIgnore}>Agregar ignore</button>
      </div>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th class="cell-nowrap">Host</th>
              <th>Path</th>
              <th class="cell-nowrap">Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#if mimosaConfig.ignore_list.length === 0}
              <tr><td colspan="4">Sin entradas.</td></tr>
            {:else}
              {#each mimosaConfig.ignore_list as rule, index}
                <tr>
                  <td class="cell-nowrap" data-label="Host">{rule.host}</td>
                  <td class="cell-truncate" title={rule.path} data-label="Path">{rule.path}</td>
                  <td class="cell-nowrap" data-label="Status">{rule.status}</td>
                  <td data-label="Accion">
                    <button class="ghost" on:click={() => removeMimosaIgnore(index)}>Quitar</button>
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>

    <div class="surface panel">
      <div class="card-head">
        <div>
          <div class="badge badge-muted">Acciones</div>
          <h3 class="card-title" style="margin-top: 12px;">Guardar cambios</h3>
        </div>
        <button class="primary" type="button" on:click={() => saveMimosaNpm(false)}>
          Guardar MimosaNPM
        </button>
      </div>
    </div>

    <div class="surface panel">
      <div class="badge">Estadisticas</div>
      {#if mimosaStatsMessage}
        <div style="margin-top: 8px; color: var(--muted); font-size: 12px;">
          {mimosaStatsMessage}
        </div>
      {/if}
      <div class="mini-grid" style="margin-top: 12px;">
        <div class="surface panel-sm">
          <strong>Por dominio</strong>
          <div style="margin-top: 10px; max-height: 220px; overflow: auto;">
            <table class="table table-compact table-responsive">
              <thead>
                <tr><th>Dominio</th><th>Hits</th></tr>
              </thead>
              <tbody>
                {#if !mimosaStats || mimosaStats.top_domains.length === 0}
                  <tr><td colspan="2">Sin datos.</td></tr>
                {:else}
                  {#each mimosaStats.top_domains as entry}
                    <tr>
                      <td data-label="Dominio">{entry.domain}</td>
                      <td data-label="Hits">{entry.count}</td>
                    </tr>
                  {/each}
                {/if}
              </tbody>
            </table>
          </div>
        </div>
        <div class="surface panel-sm">
          <strong>Por ruta</strong>
          <div style="margin-top: 10px; max-height: 220px; overflow: auto;">
            <table class="table table-compact table-responsive">
              <thead>
                <tr><th>Path</th><th>Hits</th></tr>
              </thead>
              <tbody>
                {#if !mimosaStats || mimosaStats.top_paths.length === 0}
                  <tr><td colspan="2">Sin datos.</td></tr>
                {:else}
                  {#each mimosaStats.top_paths as entry}
                    <tr>
                      <td data-label="Path">{entry.path}</td>
                      <td data-label="Hits">{entry.count}</td>
                    </tr>
                  {/each}
                {/if}
              </tbody>
            </table>
          </div>
        </div>
        <div class="surface panel-sm">
          <strong>Por status</strong>
          <div style="margin-top: 10px; max-height: 220px; overflow: auto;">
            <table class="table table-compact table-responsive">
              <thead>
                <tr><th>Status</th><th>Hits</th></tr>
              </thead>
              <tbody>
                {#if !mimosaStats || mimosaStats.top_status_codes.length === 0}
                  <tr><td colspan="2">Sin datos.</td></tr>
                {:else}
                  {#each mimosaStats.top_status_codes as entry}
                    <tr>
                      <td data-label="Status">{entry.status}</td>
                      <td data-label="Hits">{entry.count}</td>
                    </tr>
                  {/each}
                {/if}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div class="surface panel">
      <div class="badge">Eventos recientes</div>
      <div style="margin-top: 12px; overflow-x: auto;">
        <table class="table table-responsive">
          <thead>
            <tr>
              <th class="cell-nowrap">Fecha</th>
              <th class="cell-nowrap">Host</th>
              <th>Path</th>
              <th class="cell-nowrap">Status</th>
              <th class="cell-nowrap">Severidad</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#if mimosaEvents.length === 0}
              <tr><td colspan="6">Sin eventos.</td></tr>
            {:else}
              {#each mimosaEvents as event}
                <tr class={eventCovered(event) ? 'offense-match' : 'offense-no-match'}>
                  <td class="cell-nowrap" data-label="Fecha">{formatDate(event.created_at)}</td>
                  <td class="cell-nowrap" data-label="Host">{event.host || '-'}</td>
                  <td class="cell-truncate" title={event.path || '-'} data-label="Path">
                    {event.path || '-'}
                  </td>
                  <td class="cell-nowrap" data-label="Status">
                    {event.context?.status_code ?? '-'}
                  </td>
                  <td class="cell-nowrap" data-label="Severidad">{event.severity || '-'}</td>
                  <td data-label="Accion">
                    <button class="secondary btn-sm" type="button" on:click={() => applyEventToRule(event)}>
                      Usar
                    </button>
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </div>
  </div>
  {/if}
  {/if}
</div>
