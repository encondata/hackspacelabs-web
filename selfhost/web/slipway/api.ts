// Client for the Slipway API, reached through the HackSpaceLabs gateway at /api/slipway (Slipway's /api/v1).
// The gateway adds the signed-in user's Keycloak token; the browser only sends the portal's CSRF token on writes.

export type SlipwayUser = {
  id: string; username: string | null; email: string | null; full_name: string; display_name: string;
  avatar_url: string | null; is_active: boolean; roles: string[]; permissions: string[]; github_login: string | null;
  created_at: string; last_login_at: string | null;
};
export type SystemInfo = {
  version: string; github_enabled: boolean; github_service_token: boolean; host_poll_interval: number; default_deploy_root: string;
};
export type HostMetrics = {cpus?: number; cpu_percent?: number; mem_total_mb?: number; mem_percent?: number; containers_running?: number};
export type Host = {
  id: string; name: string; hostname: string; port: number; username: string; environment: string; description: string;
  deploy_root: string; auth_method: 'key' | 'password'; public_key: string | null; host_key_fingerprint: string | null;
  status: 'unknown' | 'healthy' | 'warning' | 'unreachable' | 'error'; last_checked_at: string | null; last_error: string | null;
  docker_version: string | null; os_info: string | null; metrics: HostMetrics; created_at: string;
};
export type DetectedConfig = {dockerfile?: boolean; compose_file?: string | null; files?: string[]};
export type Repo = {
  id: string; github_id: number; full_name: string; owner: string; name: string; description: string; visibility: string;
  default_branch: string; html_url: string; language: string | null; archived: boolean; pushed_at: string | null;
  detected_config: DetectedConfig; deployable: boolean; default_branch_usable: boolean; synced_at: string | null;
};
export type PortMapping = {host: number; container: number; protocol?: 'tcp' | 'udp'};
export type VolumeMapping = {source: string; target: string};
export type Instance = {
  id: string; name: string; slug: string; repository_id: string; repository: string; host_id: string; host: string; branch: string;
  build_source: 'dockerfile' | 'compose'; dockerfile_path: string; build_context: string; compose_file: string; env_keys: string[];
  env_unreadable?: boolean; ports: PortMapping[]; volumes: VolumeMapping[];
  status: 'created' | 'deploying' | 'running' | 'stopped' | 'failed'; current_commit_sha: string | null; last_deployed_at: string | null;
  created_at: string;
};
export type Deployment = {
  id: string; instance_id: string; instance_name: string; status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  branch: string; commit_sha: string | null; commit_message: string | null; commit_author: string | null; triggered_by: string | null;
  started_at: string | null; finished_at: string | null; error: string | null; created_at: string;
};
export type DeploymentDetail = Deployment & {log: string; log_offset: number};
export type AuditEvent = {
  id: string; action: string; actor: string | null; target_type: string | null; target_id: string | null; summary: string;
  ip: string | null; created_at: string;
};
export type ApiToken = {id: string; name: string; prefix: string; created_at: string; last_used_at: string | null; expires_at: string | null};
export type ActionResult = {ok: boolean; output?: string};

export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

type Detail = string | {loc?: (string | number)[]; msg?: string}[] | undefined;

function messageOf(data: {error?: string; detail?: Detail} | null, status: number): string {
  if (data?.error) return data.error;
  const detail = data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail) && detail.length) {
    return detail.map(e => {
      const where = (e.loc || []).filter(p => p !== 'body').join(' › ');
      return (where ? where + ': ' : '') + (e.msg || 'invalid value');
    }).join('; ');
  }
  if (status === 502 || status === 503 || status === 504) return 'Slipway is unavailable right now. Please try again shortly.';
  if (status === 401) return 'Your session has ended. Reload the page to sign in again.';
  return `Request failed (${status}).`;
}

export type Api = <T = unknown>(path: string, options?: {method?: string; body?: unknown}) => Promise<T>;

export function createApi(csrfToken: string): Api {
  return async function api<T>(path: string, {method = 'GET', body}: {method?: string; body?: unknown} = {}): Promise<T> {
    const headers: Record<string, string> = {Accept: 'application/json'};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && method !== 'HEAD') headers['x-csrf-token'] = csrfToken;
    let response: Response;
    try {
      response = await fetch('/api/slipway/' + path, {
        method, credentials: 'same-origin', cache: 'no-store', headers, body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError('Could not reach the portal. Check your connection and try again.', 0);
    }
    if (response.status === 204) return undefined as T;
    let data: unknown = null;
    try { data = await response.json(); } catch { /* empty or non-JSON body */ }
    if (!response.ok) throw new ApiError(messageOf(data as {error?: string; detail?: Detail} | null, response.status), response.status);
    return data as T;
  };
}

export function hasPermission(user: SlipwayUser | null, permission: string): boolean {
  if (!user || !user.is_active) return false;
  const granted = user.permissions;
  return granted.includes('*') || granted.includes(permission) || granted.includes(permission.split(':')[0] + ':*');
}

export const q = (params: Record<string, string | number | boolean | undefined | null>) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== '') search.set(key, String(value));
  const text = search.toString();
  return text ? '?' + text : '';
};

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return '—';
  const seconds = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (!Number.isFinite(seconds)) return '—';
  if (seconds < 45) return 'just now';
  const units: [number, string][] = [[60, 'minute'], [3600, 'hour'], [86400, 'day'], [604800, 'week']];
  if (seconds < 3600) return plural(Math.round(seconds / 60), units[0][1]);
  if (seconds < 86400) return plural(Math.round(seconds / 3600), units[1][1]);
  if (seconds < 604800) return plural(Math.round(seconds / 86400), units[2][1]);
  return new Date(iso).toLocaleDateString('en-US', {month: 'short', day: 'numeric', year: 'numeric'});
}
const plural = (n: number, unit: string) => `${n} ${unit}${n === 1 ? '' : 's'} ago`;

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-US', {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'});
}

export function duration(start: string | null, end: string | null): string {
  if (!start) return '—';
  const seconds = Math.max(0, Math.round(((end ? Date.parse(end) : Date.now()) - Date.parse(start)) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return minutes < 60 ? `${minutes}m ${seconds % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

// POSIX shell single-quoting, for the host setup snippet.
export const shellQuote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
