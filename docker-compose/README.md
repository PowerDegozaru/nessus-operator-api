````markdown
## Docker Compose Quick-Start

This stack spins up **both** the custom API server and the Nessus MCP
(TypeScript) bridge in one command—ideal for demos or CI pipelines.

---

### 1  Prerequisites

* Docker Engine 20.10+  
* Docker Compose v2 (comes with Docker Desktop)

---

### 2  Configuration

1. **Copy the sample TOML**

   ```bash
   cp api-server-config.example.toml api-server-config.toml
````

2. **Edit the file**

   * Use `https://host.docker.internal:<port>` for `nessus.url` when
     Nessus is running on **your host machine** (macOS/Windows only).
   * Make sure `headless_operator = false`—Playwright needs a
     virtual display inside the container.

3. *(Optional)* open `compose.yaml` and expose the API port if you want
   to call it from outside the Compose network, e.g.

   ```yaml
   services:
     api:
       ports:
         - "8000:8000"
   ```

---

### 3  Running the stack

```bash
docker compose up -d              # detached
```

| Action                 | Command                                                       |
| ---------------------- | ------------------------------------------------------------- |
| **View logs (follow)** | `docker compose logs -f api`<br/>`docker compose logs -f mcp` |
| **Stop everything**    | `docker compose down`                                         |

---

### 4  Integrating with Genie MCP

*For automated launches,* point the MCP JSON config’s **`command`**
argument at the helper script:

```jsonc
{
  "command": "bash",
  "args": ["start-mcp-stdio.sh"],
  "disabled": false
}
```

The script simply `docker attach`es to the running MCP container so that
STDIO is bridged back to the parent Genie process.

**Manual alternative**

```bash
docker attach nessus-compose-mcp-1
```

*(Replace the container name if you changed the service name.)*

---

### 5  Debugging tips

* **General logs**

  ```bash
  docker logs --follow nessus-compose-api-1
  docker logs --follow nessus-compose-mcp-1
  ```

* **Playwright + headless**

  Even though the browser runs headless in Docker, agent step logs are
  streamed to `nessus-compose-api-1`; inspect them for selector errors
  or navigation timeouts.

* **Container names**

  Default pattern is `nessus-compose-<service>-1`.
  Run `docker ps` to verify.

---

> **Need full-screen Playwright?**
> Run the stack natively (see manual setup in the main README) where you
> can launch a headed browser for interactive debugging.

```
```
