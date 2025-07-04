/**
 * Vulnerability-related MCP tools
 */

import { getVulnerabilityDetails } from '../nessus-api.js';
import { handleNessusApiError } from '../utils/error-handling.js';
import { z } from 'zod';

/* ───────────────────────── schemas ──────────────────────── */

const vulnIdSchema = z.string().min(1);

/* ───────────────────────── get details ───────────────────── */

export const getVulnerabilityDetailsToolSchema = {
  name: 'get_vulnerability_details',
  description: 'Get detailed information about a specific vulnerability',
  inputSchema: {
    type: 'object',
    properties: {
      vulnerability_id: { type: 'string', description: 'e.g. CVE-2024-12345' }
    },
    required: ['vulnerability_id']
  }
};

export const getVulnerabilityDetailsToolHandler = async (args: Record<string, unknown>) => {
  try {
    const vulnId  = vulnIdSchema.parse(args.vulnerability_id);
    const details = await getVulnerabilityDetails(vulnId);
    return { content: [{ type: 'text', text: JSON.stringify(details, null, 2) }] };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return { content: [{ type: 'text', text: `Error: ${mcpErr.message}` }], isError: true };
  }
};

/* ───────────────────────── search vulns ──────────────────── */

export const searchVulnerabilitiesToolSchema = {
  name: 'search_vulnerabilities',
  description: 'Search for vulnerabilities by keyword',
  inputSchema: {
    type: 'object',
    properties: { keyword: { type: 'string', description: 'Search keyword' } },
    required: ['keyword']
  }
};

export const searchVulnerabilitiesToolHandler = async (args: Record<string, unknown>) => {
  try {
    const keyword = z.string().min(2).parse(args.keyword).toLowerCase();

    const { vulnerabilities } = await import('../mock-data.js');
    const matches = vulnerabilities.filter(
      (v) =>
        v.name.toLowerCase().includes(keyword) ||
        v.description.toLowerCase().includes(keyword)
    );

    if (matches.length === 0) {
      return { content: [{ type: 'text', text: `No hits for "${keyword}"` }] };
    }

    const listing = matches
      .map(
        (v, i) =>
          `${i + 1}. ${v.name} (${v.id}) | ${v.severity.toUpperCase()} | CVSS ${v.cvss_score}`
      )
      .join('\n');

    return {
      content: [
        {
          type: 'text',
          text:
            `Found ${matches.length} vulnerabilities for "${keyword}":\n\n` +
            listing +
            `\n\nUse "get_vulnerability_details" with the desired id for full info.`
        }
      ]
    };
  } catch (err) {
    const mcpErr = handleNessusApiError(err);
    return { content: [{ type: 'text', text: `Error: ${mcpErr.message}` }], isError: true };
  }
};
