# Docker Compose
This docker compose allows for quick deployment of the Nessus MCP server integrated with the custom API.

## Running
Complete the [Compose Configuration](#config) first.

`start-mcp-stdio.sh` is a convienient executable to be passed as part of the "command" parameter of the MCP config. It is Bash script tested to work on Linux.

Otherwise, we have to manually run
```sh
docker compose up -d
```
and then pass the following as "command" into the MCP config:
```sh
docker attach {name of MCP container}
```
where the container name usually defaults to `nessus-compose-mcp-1` (check `docker ps`).


## Config
`api-server-config.toml` needs to be created, use `https://host.docker.internal:{port}` if the Nessus server is running in your host machine (e.g. in `https://localhost:{port}`).

The API server will be running in a containerised environment, and by default will not expose any ports to the host machine (you can expose it in the `compose.yaml` file for debugging purposes).

> [!WARNING]
> `headless_operator` cannot be `true` when running in Docker


## Debugging
It is best to debug the project when running natively (not in Docker), however, we can make use of the docker logging feature to get an idea of what is going on with the servers.

```sh
docker logs --follow {container name}
```
will show a running log of the container.

> The container name should by default be `nessus-compose-api-1` for the API Server and `nessus-compose-mcp-1` for the MCP Server.
> 
> Use `docker ps` to check which containers are currently running

Though Browser Use can only run headless in Docker, the logs should show the progress of the browser agent for debugging.

