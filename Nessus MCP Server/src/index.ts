#!/usr/bin/env node
/**
 * Nessus MCP Server
 *
 * This server exposes an MCP interface that talks to a FastAPI back-end.
 * If MCP_API_URL is undefined (or MCP_FORCE_MOCK=true) we run in mock mode.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { initializeNessusApi } from './nessus-api.js';
import { handleNessusApiError } from './utils/error-handling.js';

/* ------------------------------------------------------------------ */
/*  Tool schemas & handlers                                           */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Initialise the Nessus API client                                  */
/* ------------------------------------------------------------------ */

const initializeApi = () => {
  const apiUrl       = process.env.MCP_API_URL;      // FastAPI façade
  const forceMock    = process.env.MCP_FORCE_MOCK === 'true';

  const useMock = forceMock || !apiUrl;

  return initializeNessusApi({
    baseUrl: apiUrl ?? 'http://localhost:8000',      // ignored in mock mode
    useMock
  });
};

/* ------------------------------------------------------------------ */
/*  Create the MCP server                                             */
/* ------------------------------------------------------------------ */

const createServer = () => {
  const server = new Server(
    { name: 'nessus-server', version: '1.0.0' },
    { capabilities: { tools: {} } }
  );

  /* -------- list tools -------- */
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

  /* -------- call tool -------- */
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    try {
      const { name, arguments: args = {} } = req.params;

      switch (name) {
        case 'list_scan_templates':   return await listScanTemplatesToolHandler();
        case 'start_scan':            return await startScanToolHandler(args);
        case 'get_scan_status':       return await getScanStatusToolHandler(args);
        case 'get_scan_results':      return await getScanResultsToolHandler(args);
        case 'list_scans':            return await listScansToolHandler();
        case 'get_vulnerability_details':
          return await getVulnerabilityDetailsToolHandler(args);
        case 'search_vulnerabilities':
          return await searchVulnerabilitiesToolHandler(args);
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

  return server;
};

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

async function main() {
  try {
    const apiCfg = initializeApi();
    console.error(
      `Nessus MCP Server starting in ${apiCfg.useMock ? 'mock' : 'real API'} mode` +
      (apiCfg.useMock ? '' : ` (${apiCfg.baseUrl})`)
    );

    const server    = createServer();
    const transport = new StdioServerTransport();

    await server.connect(transport);
    console.error('Nessus MCP Server running on stdio');

    process.on('SIGINT', async () => {
      console.error('Shutting down Nessus MCP Server…');
      await server.close();
      process.exit(0);
    });
  } catch (err) {
    console.error('Fatal error starting Nessus MCP Server:', err);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Unhandled error in Nessus MCP Server:', err);
  process.exit(1);
});
