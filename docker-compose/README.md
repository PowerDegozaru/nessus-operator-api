# Docker Compose
This docker compose allows for quick deployment of the Nessus MCP server integrated with the custom API.

The `start-mcp-stdio.sh` script is the executable to be passed as part of the "command" parameter of the MCP config.

## Configs:
`api-server-config.toml` needs to be created, use `https://host.docker.internal:{port}` if the Nessus server is running in your host machine (e.g. in `https://localhost:{port}`).

The API server will be running in a containerised environment, and by default will not expose any ports to the host machine (you can expose it in the `compose.yaml` file for debugging purposes).

