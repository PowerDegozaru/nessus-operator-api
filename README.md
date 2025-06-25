# Setup Guide

This file covers two ways to bring up the Genie Cyber Tester V3 – Nessus Module: a one-shot Docker Compose deployment (recommended) and a fully manual path for environments where containers are not an option.

---------------------------------------------------------------------------
DOCKER COMPOSE
---------------------------------------------------------------------------

For docker setup, follow the docker-compose\README.md file

---------------------------------------------------------------------------
MANUAL SETUP (WITHOUT DOCKER)
---------------------------------------------------------------------------

API Server
-----------------

   # install Python dependencies
   pip install -r requirements.txt

   # copy and edit server configuration (remember to cd into api-server)
   cp config.example.toml config.toml

   # run with auto-reload
   fastapi dev src/main.py

   # or: (If you are facing issue with playwright)
   uvicorn main:app --app-dir src --host 127.0.0.1 --port 8000

Node MCP Server
---------------

   cd nessus-mcp-server

   # install JavaScript dependencies
   npm install

   # build TypeScript
   npm run build                      # output in dist/

The MCP config include something like:

   {
     "mcpServers": {
       "nessus": {
         "command": "node",
         "args": ["dist/index.js"],
         "env": {
           "MCP_API_URL": "http://localhost:8000",
           "MCP_FORCE_MOCK": "false"
         },
         "disabled": false
       }
     }
   }

After setting up and running both, you should be able to use the API server to interact with the MCP server. 