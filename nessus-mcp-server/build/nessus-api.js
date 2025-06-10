/**
 * Modernised Nessus client – works with the FastAPI back-end in main.py
 * The mock layer is still available by setting useMock = true.
 */
import { scanTemplates, createMockScan, getMockScanStatus, getMockScanResults, getMockVulnerabilityDetails, mockScans, } from "./mock-data.js";
/* ------------------------------------------------------------------ */
/*  Configuration & helpers                                           */
/* ------------------------------------------------------------------ */
const defaultConfig = {
    baseUrl: "http://localhost:8000", // change to prod URL if needed
    useMock: true,
};
let cfg = { ...defaultConfig };
export const initializeNessusApi = (userCfg = {}) => {
    cfg = { ...defaultConfig, ...userCfg };
    console.info(`Nessus API initialised – mode: ${cfg.useMock ? "mock" : "real"} (${cfg.baseUrl})`);
    return cfg;
};
/** Low-level fetch wrapper that appends token / API-Key headers automatically */
const request = async (path, init = {}, expectJson = true) => {
    if (cfg.useMock)
        throw new Error("Real HTTP calls disabled – cfg.useMock === true");
    const headers = {
        "Content-Type": "application/json",
        ...init.headers,
    };
    // Authentication – prefer session token, then explicit API keys
    if (cfg.token) {
        headers["X-Cookie"] = `token=${cfg.token};`;
    }
    else if (cfg.accessKey && cfg.secretKey) {
        headers["X-ApiKeys"] = `accessKey=${cfg.accessKey}; secretKey=${cfg.secretKey};`;
    }
    const res = await fetch(`${cfg.baseUrl}${path}`, { ...init, headers });
    if (!res.ok) {
        const body = await res.text();
        throw new Error(`Request ${init.method ?? "GET"} ${path} failed ${res.status}: ${body.slice(0, 200)}`);
    }
    return expectJson ? res.json() : undefined;
};
/* ------------------------------------------------------------------ */
/*  Public API – the functions your front-end will import             */
/* ------------------------------------------------------------------ */
/** Authenticate against /session and cache the returned token */
export const login = async (opts) => {
    if (cfg.useMock)
        return; // no-op in mock mode
    const token = await request("/session", {
        method: "POST",
        body: JSON.stringify(opts),
    });
    cfg.token = token;
};
/** GET /list_scan_templates */
export const getScanTemplates = async () => {
    if (cfg.useMock)
        return { templates: scanTemplates };
    return request("/list_scan_templates");
};
/**
 * POST /start_scan
 * @param target             IP / hostname
 * @param scanType           Template title, e.g. "Basic Network Scan"
 * @param scanNamePrefix     Optional – defaults to "nessus-controller"
 */
export const startScan = async (target, scanType, scanNamePrefix = "nessus-controller") => {
    if (cfg.useMock) {
        const id = createMockScan(target, scanType);
        return { ok: true, scan_id: id, scan_name: `${scanNamePrefix}-${id}` };
    }
    return request("/start_scan", {
        method: "POST",
        body: JSON.stringify({ target, scan_type: scanType, scan_name_prefix: scanNamePrefix }),
    });
};
/** GET /scan_status?scan_id= */
export const getScanStatus = async (scanId) => {
    if (cfg.useMock)
        return getMockScanStatus(String(scanId));
    return request(`/scan_status?scan_id=${scanId}`);
};
/** GET /scan_results?scan_id= */
export const getScanResults = async (scanId) => {
    if (cfg.useMock)
        return getMockScanResults(String(scanId));
    return request(`/scan_results?scan_id=${scanId}`);
};
/** GET /list_scans[?folder_id=] */
export const listScans = async (folderId) => {
    if (cfg.useMock) {
        const scans = Array.from(mockScans.values()).map((s) => ({
            id: s.id,
            target: s.target,
            type: s.type,
            status: s.status,
            created: s.created,
        }));
        return { scans };
    }
    const qs = folderId ? `?folder_id=${folderId}` : "";
    return request(`/list_scans${qs}`);
};
/** GET /folders – added convenience wrapper */
export const listFolders = async () => {
    if (cfg.useMock)
        throw new Error("Folders not implemented in mock layer yet");
    return request("/folders");
};
/** Create a folder if it does not yet exist (helper around /folders/getid) */
export const ensureFolder = async (name) => {
    if (cfg.useMock)
        throw new Error("Not supported in mock mode");
    const qs = `?name=${encodeURIComponent(name)}&create_if_not_exists=true`;
    return request(`/folders/getid${qs}`);
};
/** Optional helper that just pings /list_scan_templates to check health */
export const checkApiStatus = async () => {
    if (cfg.useMock)
        return { status: "ok", mode: "mock" };
    try {
        await getScanTemplates();
        return { status: "ok", mode: "real" };
    }
    catch (e) {
        return { status: "error", mode: "real", message: e.message };
    }
};
/** placeholder – no FastAPI endpoint yet */
export const getVulnerabilityDetails = async (cve) => {
    if (cfg.useMock)
        return getMockVulnerabilityDetails(cve);
    throw new Error("Endpoint /vulnerability_details not implemented server-side");
};
