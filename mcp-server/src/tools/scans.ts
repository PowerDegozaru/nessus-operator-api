/**
 * Scan-related MCP tools
 */

import { z } from 'zod';
import {
  getScanTemplates,
  startScan,
  getScanStatus,
  getScanResults,
  listScans
} from '../nessus-api.js';
import { handleNessusApiError } from '../utils/error-handling.js';

/* ───────────────────────── helpers ───────────────────────── */

const targetSchema   = z.string().min(1);
const scanTypeSchema = z.string().min(1);
const scanIdSchema   = z.union([z.number().int(), z.string().min(1)]);

/* ───────────────────────── list templates ────────────────── */

export const listScanTemplatesToolSchema = {
  name: 'list_scan_templates',
  description: 'List available Nessus scan templates',
  inputSchema: { type: 'object', properties: {} }
};

export const listScanTemplatesToolHandler = async () => {
  try {
    const { templates } = await getScanTemplates();
    return {
      content: [{ type: 'text', text: JSON.stringify(templates, null, 2) }]
    };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return {
      content: [{ type: 'text', text: `Error: ${mcpErr.message}` }],
      isError: true
    };
  }
};

/* ───────────────────────── start scan ────────────────────── */

export const startScanToolSchema = {
  name: 'start_scan',
  description: 'Start a new vulnerability scan against a target',
  inputSchema: {
    type: 'object',
    properties: {
      target   : { type: 'string', description: 'IP / hostname' },
      scan_type: { type: 'string', description: 'Template title' }
    },
    required: ['target', 'scan_type']
  }
};

export const startScanToolHandler = async (args: Record<string, unknown>) => {
  try {
    const target   = targetSchema.parse(args.target);
    const scanType = scanTypeSchema.parse(args.scan_type);

    const res = await startScan(target, scanType);
    return { content: [{ type: 'text', text: JSON.stringify(res, null, 2) }] };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return { content: [{ type: 'text', text: `Error: ${mcpErr.message}` }], isError: true };
  }
};

/* ───────────────────────── get scan status ───────────────── */

export const getScanStatusToolSchema = {
  name: 'get_scan_status',
  description: 'Check the status of a running scan',
  inputSchema: {
    type: 'object',
    properties: { scan_id: { type: 'string', description: 'Scan ID' } },
    required: ['scan_id']
  }
};

export const getScanStatusToolHandler = async (args: Record<string, unknown>) => {
  try {
    const scanId = scanIdSchema.parse(args.scan_id);
    const status = await getScanStatus(scanId);
    return { content: [{ type: 'text', text: JSON.stringify(status, null, 2) }] };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return { content: [{ type: 'text', text: `Error: ${mcpErr.message}` }], isError: true };
  }
};

/* ───────────────────────── get scan results ──────────────── */

export const getScanResultsToolSchema = {
  name: 'get_scan_results',
  description: 'Get the results of a completed scan',
  inputSchema: {
    type: 'object',
    properties: { scan_id: { type: 'string', description: 'Scan ID' } },
    required: ['scan_id']
  }
};

export const getScanResultsToolHandler = async (args: Record<string, unknown>) => {
  try {
    const scanId  = scanIdSchema.parse(args.scan_id);
    const results = await getScanResults(scanId);
    return { content: [{ type: 'text', text: JSON.stringify(results, null, 2) }] };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return { content: [{ type: 'text', text: `Error: ${mcpErr.message}` }], isError: true };
  }
};

/* ───────────────────────── list scans ────────────────────── */

export const listScansToolSchema = {
  name: 'list_scans',
  description: 'List all scans and their status',
  inputSchema: { type: 'object', properties: {} }
};

export const listScansToolHandler = async () => {
  try {
    const { scans } = await listScans();
    return { content: [{ type: 'text', text: JSON.stringify(scans, null, 2) }] };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return { content: [{ type: 'text', text: `Error: ${mcpErr.message}` }], isError: true };
  }
};
