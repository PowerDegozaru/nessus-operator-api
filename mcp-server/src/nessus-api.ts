/**
 * Thin client for our FastAPI Nessus façade.
 * Automatically adds auth headers and converts FastAPI responses into a
 * shape expected by the MCP tool-handlers.
 */

import {
  scanTemplates,
  createMockScan,
  getMockScanStatus,
  getMockScanResults,
  getMockVulnerabilityDetails,
  mockScans
} from './mock-data.js';

/* ─────────────────────── types ─────────────────────── */

export interface NessusConfig {
  /** Root URL of the FastAPI service */
  baseUrl: string;
  /** Token returned by POST /session */
  token?: string;
  /** Optional explicit Nessus API keys – rarely needed */
  accessKey?: string;
  secretKey?: string;
  /** If true, bypass HTTP calls and return mock data */
  useMock?: boolean;
}

export interface LoginOptions {
  username: string;
  password: string;
}

/** Common structure returned by MCP tool-handlers */
export interface ApiErrorShape { detail: string }

/* ─────────────────────── errors ─────────────────────── */

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/* ───────────────────── configuration ───────────────── */

const defaultConfig: NessusConfig = {
  baseUrl: 'http://localhost:8000',
  useMock: true
};

let cfg: NessusConfig = { ...defaultConfig };

export const initializeNessusApi = (userCfg: Partial<NessusConfig> = {}) => {
  cfg = { ...defaultConfig, ...userCfg };
  return cfg;
};

/* ───────────────────── fetch helper ─────────────────── */

const request = async <T>(
  path: string,
  init: RequestInit = {},
  expectJson = true
): Promise<T> => {
  if (cfg.useMock)
    throw new Error('Real HTTP calls disabled – cfg.useMock === true');

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init.headers as Record<string, string> | undefined)
  };

  // Auth – prefer session token
  if (cfg.token) {
    headers['X-Cookie'] = `token=${cfg.token};`;
  } else if (cfg.accessKey && cfg.secretKey) {
    headers['X-ApiKeys'] = `accessKey=${cfg.accessKey}; secretKey=${cfg.secretKey};`;
  }

  let res: Response;
  try {
    res = await fetch(`${cfg.baseUrl}${path}`, { ...init, headers });
  } catch (e) {
    throw new HttpError(0, `Network error to ${path}: ${(e as Error).message}`);
  }

  if (!res.ok) {
    const body = await res.text();
    throw new HttpError(res.status, body.slice(0, 500));
  }

  if (expectJson && res.status !== 204) {
    return res.json() as Promise<T>;
  }
  // eslint-disable-next-line @typescript-eslint/consistent-type-assertions
  return undefined as unknown as T;
};

/* ───────────────────── public API ───────────────────── */

/** POST /session */
export const login = async (opts: LoginOptions): Promise<void> => {
  if (cfg.useMock) return;
  cfg.token = await request<string>('/session', {
    method: 'POST',
    body: JSON.stringify(opts)
  });
};

/** GET /list_scan_templates */
export const getScanTemplates = async () => {
  if (cfg.useMock) return { templates: scanTemplates };

  const templates = await request<{ title: string; uuid: string; desc: string }[]>(
    '/list_scan_templates'
  );
  return { templates };                       // normalise shape
};

/** POST /start_scan */
export const startScan = async (
  target: string,
  scanType: string,
  scanNamePrefix = 'nessus-controller'
) => {
  if (cfg.useMock) {
    const id = createMockScan(target, scanType);
    return { ok: true, scan_id: id, scan_name: `${scanNamePrefix}-${id}` };
  }

  return request<{
    ok: boolean;
    scan_id: number;
    scan_name: string;
  }>('/start_scan', {
    method: 'POST',
    body: JSON.stringify({
      target,
      scan_type: scanType,
      scan_name_prefix: scanNamePrefix
    })
  });
};

/** GET /scan_status */
export const getScanStatus = async (scanId: number | string) => {
  if (cfg.useMock) return getMockScanStatus(String(scanId));
  return request(`/scan_status?scan_id=${encodeURIComponent(scanId)}`);
};

/** GET /scan_results */
export const getScanResults = async (scanId: number | string) => {
  if (cfg.useMock) return getMockScanResults(String(scanId));
  return request(`/scan_results?scan_id=${encodeURIComponent(scanId)}`);
};

/** GET /list_scans */
export const listScans = async (folderId?: number) => {
  if (cfg.useMock) {
    return { scans: Array.from(mockScans.values()) };
  }
  const qs = folderId ? `?folder_id=${folderId}` : '';
  const scans = await request(`/list_scans${qs}`);
  return { scans };                           // normalise shape
};

/** GET /folders */
export const listFolders = async () => {
  if (cfg.useMock) throw new Error('Folders not mocked');
  return request('/folders');
};

/** Ensure folder exists, return its numeric id */
export const ensureFolder = async (name: string): Promise<number> => {
  if (cfg.useMock) throw new Error('ensureFolder not mocked');
  const qs = `?name=${encodeURIComponent(name)}&create_if_not_exists=true`;
  return request<number>(`/folders/getid${qs}`);
};

/** Simple health-check helper */
export const checkApiStatus = async () => {
  if (cfg.useMock) return { status: 'ok', mode: 'mock' };
  try {
    await getScanTemplates();
    return { status: 'ok', mode: 'real' };
  } catch (e) {
    return { status: 'error', mode: 'real', message: (e as Error).message };
  }
};

/** placeholder – server endpoint not implemented */
export const getVulnerabilityDetails = async (cve: string) => {
  if (cfg.useMock) return getMockVulnerabilityDetails(cve);
  throw new Error('Endpoint /vulnerability_details not implemented server-side');
};
