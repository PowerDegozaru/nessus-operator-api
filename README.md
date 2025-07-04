# Genie Cyber Tester V3 — **Nessus Module**

> Launch Tenable Nessus scans and collect results through a unified API  
> – with optional headless browser automation when the REST API falls short.

---

## Table of Contents
1. [Quick start (with Docker Compose)](#quick-start-with-docker-compose)
2. [Manual setup (without Docker)](#manual-setup-without-docker)
3. [Directory layout](#directory-layout)
4. [Troubleshooting & tips](#troubleshooting--tips)

---

## Prerequisites – **Read me first 👀**

Before you run either Docker Compose **or** the manual workflow,
populate a few secrets and connection details.

## Remember to Edit `api-server/config.toml` beforehand

## Quick start (with Docker Compose)

The **easiest** way to run everything—including the API server, Playwright
browsers, and the MCP bridge—is the provided Compose file.

```bash
# 1. Copy the sample config once
cp api-server/config.example.toml api-server/config.toml
#    … edit it to match your Nessus instance & API keys …

# 2. Spin it up
docker compose up --build
````

➡️ See **[`docker-compose/README.md`](docker-compose/README.md)** for
architecture diagrams, environment variables and production tips.

---

## Manual setup (without Docker)

> Use this path on air-gapped servers or when corporate policy forbids
> containers.

### 1  API Server (Python 3.11+)

```bash
# From repo root
cd api-server

# Install Python dependencies
pip install -r requirements.txt

# Copy + edit config
cp config.toml.example config.toml
vim config.toml   # set Nessus URL, API keys, etc.

# Run with live-reload (dev only)
fastapi dev src/main.py

# — or — (if Playwright is facing issue)
uvicorn main:app --app-dir src --host 127.0.0.1 --port 8000
```

### 2  MCP Server (Node 18+)

```bash
cd mcp-server

# Install JS deps
npm ci

# Compile TypeScript → dist/
npm run build
```

**Sample MCP launcher snippet**

```jsonc
{
  "mcpServers": {
    "nessus": {
      "command": "node",
      "args": [
        "C:\\path\\to\\mcp-server\\dist\\index.js"
      ],
      "env": {
        "MCP_API_URL": "http://localhost:8000",
        "MCP_FORCE_MOCK": "false"
      },
      "disabled": false
    }
  }
}
```

Start both processes and the API (`localhost:8000`) can now
talk to the MCP server.

---

## Directory layout

```
.
├── api-server/            # FastAPI app + browser operator
│   ├── src/
│   │   ├── main.py        # API routes
│   │   ├── service.py     # Pure-Nessus helpers
│   │   └── browser_tasks.py
│   └── config.example.toml
├── nessus-mcp-server/     # TypeScript source
├── docker-compose/        # Container stack & docs
```

---

## Troubleshooting & tips

| Issue                                                            | Quick fix                                                                                                 |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Playwright browsers fail to launch** (often on headless Linux) | `playwright install` then `playwright install-deps`                                                       |
| Windows + FastAPI hot-reload error                               | Use the `uvicorn …` command above; the bundled event-loop policy in `main.py` will kick in automatically. |
| “`SSL: CERTIFICATE_VERIFY_FAILED`”                               | Set `ssl_verify = false` in `config.toml` *only* if your Nessus instance has a self-signed cert.          |
| MCP server cannot reach the API                                  | Confirm `MCP_API_URL` and that no corporate proxy is blocking `localhost`.                                |


