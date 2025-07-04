#!/usr/bin/env node
/**
 * Nessus MCP Server – entry-point
 *
 * Exposes Model-Context-Protocol (MCP) tools that front-end LLMs can
 * call.  Bridges to a FastAPI backend (or a local mock layer).
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

import { initializeNessusApi } from './nessus-api.js';
import { handleNessusApiError } from './utils/error-handling.js';

/* ──────────────────────────────────────────────────────────────────── */
/*  Tool schemas & handlers                                            */
/* ──────────────────────────────────────────────────────────────────── */

import {
  listScanTemplatesToolSchema,
  listScanTemplatesToolHandler,
  startScanToolSchema,
  startScanToolHandler,
  getScanStatusToolSchema,
  getScanStatusToolHandler,
  getScanResultsToolSchema,
  getScanResultsToolHandler,
  listScansToolSchema,
  listScansToolHandler
} from './tools/scans.js';

import {
  getVulnerabilityDetailsToolSchema,
  getVulnerabilityDetailsToolHandler,
  searchVulnerabilitiesToolSchema,
  searchVulnerabilitiesToolHandler
} from './tools/vulnerabilities.js';

/* ──────────────────────────────────────────────────────────────────── */
/*  Initialise the Nessus API client                                   */
/* ──────────────────────────────────────────────────────────────────── */

const apiCfg = initializeNessusApi({
  baseUrl  : process.env.MCP_API_URL ?? 'http://localhost:8000',
  useMock  : process.env.MCP_FORCE_MOCK === 'true' || !process.env.MCP_API_URL
});

console.info(
  `Nessus MCP Server starting in ${apiCfg.useMock ? 'mock' : 'real API'} mode`,
  !apiCfg.useMock ? `→ ${apiCfg.baseUrl}` : ''
);

/* ──────────────────────────────────────────────────────────────────── */
/*  MCP server setup                                                   */
/* ──────────────────────────────────────────────────────────────────── */

const server = new Server(
  { name: 'nessus-server', version: '1.1.0' },
  { capabilities: { tools: {} } }
);

/* ---- /list_tools ---- */
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    listScanTemplatesToolSchema,
    startScanToolSchema,
    getScanStatusToolSchema,
    getScanResultsToolSchema,
    listScansToolSchema,
    getVulnerabilityDetailsToolSchema,
    searchVulnerabilitiesToolSchema
  ]
}));

/* ---- /call_tool ---- */
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;
  try {
    switch (name) {
      case 'list_scan_templates':      return listScanTemplatesToolHandler();
      case 'start_scan':               return startScanToolHandler(args);
      case 'get_scan_status':          return getScanStatusToolHandler(args);
      case 'get_scan_results':         return getScanResultsToolHandler(args);
      case 'list_scans':               return listScansToolHandler();
      case 'get_vulnerability_details':return getVulnerabilityDetailsToolHandler(args);
      case 'search_vulnerabilities':   return searchVulnerabilitiesToolHandler(args);
      default:
        return {
          content: [{ type: 'text', text: `Error: Unknown tool "${name}"` }],
          isError: true
        };
    }
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return {
      content: [{ type: 'text', text: `Error: ${mcpErr.message}` }],
      isError: true
    };
  }
});

/* ──────────────────────────────────────────────────────────────────── */
/*  Bootstrap                                                          */
/* ──────────────────────────────────────────────────────────────────── */

(async () => {
  const transport = new StdioServerTransport();
  try {
    await server.connect(transport);
    console.error('Nessus MCP Server listening on stdio');

    process.on('SIGINT', async () => {
      console.error('Shutting down Nessus MCP Server - SIGINT');
      await server.close();
      process.exit(0);
    });
  } catch (err) {
    console.error('Fatal MCP server error:', err);
    process.exit(1);
  }
})();
