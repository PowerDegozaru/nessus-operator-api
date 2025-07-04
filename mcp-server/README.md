# Nessus MCP Server

A Model Context Protocol (MCP) server for interacting with the Tenable Nessus vulnerability scanner. This server allows AI assistants to perform vulnerability scanning and analysis through the MCP protocol.

## Features

- **Vulnerability Scanning**: Start and monitor vulnerability scans against specified targets
- **Scan Management**: List, track, and retrieve results from vulnerability scans
- **Vulnerability Analysis**: Search for and get detailed information about specific vulnerabilities
- **Mock Mode**: Fully functional mock mode for testing without a Nessus API key

## Tools

The server provides the following tools:

| Tool Name                   | Description                                             |
| --------------------------- | ------------------------------------------------------- |
| `list_scan_templates`       | List available Nessus scan templates                    |
| `start_scan`                | Start a new vulnerability scan against a target         |
| `get_scan_status`           | Check the status of a running scan                      |
| `get_scan_results`          | Get the results of a completed scan                     |
| `list_scans`                | List all scans and their status                         |
| `get_vulnerability_details` | Get detailed information about a specific vulnerability |
| `search_vulnerabilities`    | Search for vulnerabilities by keyword                   |

## Installation

### Prerequisites

- Node.js 16 or higher
- TypeScript (for development)

## Usage

### Running in Mock Mode

By default, the server runs in mock mode, which doesn't require a Nessus API key:

```
node build/index.js
```

For mock mode, you can omit the `env` section.

## Example Interactions

### Starting a Scan

```
start_scan:
  target: 192.168.1.1
  scan_type: basic-network-scan
```

### Getting Scan Results

```
get_scan_results:
  scan_id: scan-1234567890
```

### Searching for Vulnerabilities

```
search_vulnerabilities:
  keyword: log4j
```

## Development

### Project Structure

- `src/index.ts`: Main server entry point
- `src/nessus-api.ts`: Nessus API client with mock fallback
- `src/mock-data.ts`: Mock vulnerability data for testing
- `src/tools/`: Tool implementations
- `src/utils/`: Utility functions

### Adding New Tools

1. Define the tool schema and handler in the appropriate file in `src/tools/`
2. Import and register the tool in `src/index.ts`

## License

MIT

## Disclaimer

This server is not affiliated with or endorsed by Tenable. Nessus is a trademark of Tenable, Inc.
