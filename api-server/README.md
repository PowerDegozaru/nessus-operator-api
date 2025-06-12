
Start the server in development mode using:
```sh
fastapi dev src/main.py
```

Nessus MCP Setup
1. cd to the nessus-mcp-server directory
   ```
   cd nessus-mcp-server
   ```

2. Install dependencies:

   ```
   npm install
   ```

3. Build the server:
   ```
   npm run build
   ```

Remember to setup the MCP Server configuration:

{
  "mcpServers": {
    "nessus": {
      "command": "node",
      "args": [
        "Insert the MCP server index.js location"
      ],
      "env": {
        "MCP_API_URL": "http://localhost:8000",
        "MCP_FORCE_MOCK": "false"
      },
      "disabled": false
    }
  }
}