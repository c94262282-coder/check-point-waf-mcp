# Check Point WAF MCP Server

<!-- Badges placeholder -->
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that provides tools for managing Check Point WAF through its GraphQL API.

## Features

### Queries
- **getAssets** - List all WAF assets with optional filtering
- **getAsset** - Get detailed information about a specific asset
- **getProfiles** - List all WAF security profiles
- **getProfile** - Get details of a specific security profile
- **getPractices** - List all security practices
- **getPractice** - Get details of a specific security practice
- **getTuningSuggestions** - Get tuning suggestions for an asset
- **getLogEntries** - Query WAF log entries with filters
- **getCertificates** - List all uploaded certificates
- **getPendingChanges** - View unpublished pending changes

### Mutations
- **createAsset** - Create a new web application or web API asset
- **updateAsset** - Update an existing asset's configuration
- **deleteAsset** - Delete an asset
- **createProfile** - Create a new security profile
- **updateProfile** - Update a security profile
- **deleteProfile** - Delete a security profile
- **applyTuningSuggestion** - Accept a tuning suggestion
- **publishChanges** - Publish all pending changes
- **discardChanges** - Discard all pending changes

### Utility
- **getGraphQLSchema** - Introspect the Check Point WAF GraphQL schema

## Prerequisites

- **Python 3.11+**
- **Check Point Infinity Portal API key** - A client ID and access key pair from the [Infinity Portal](https://portal.checkpoint.com/)

## Installation

### Using uv (recommended)

```bash
uvx checkpoint-waf-mcp
```

### Using pip

```bash
pip install checkpoint-waf-mcp
```

## Configuration

The server is configured via environment variables:

| Variable | Description | Required |
|---|---|---|
| `CHECKPOINT_CLIENT_ID` | API client ID from Infinity Portal | Yes |
| `CHECKPOINT_ACCESS_KEY` | API access key from Infinity Portal | Yes |
| `CHECKPOINT_REGION` | Data center region | No (default: `us`) |

### Available Regions

| Region Code | Location |
|---|---|
| `us` | United States |
| `eu` | Europe |
| `ap` | Asia Pacific |
| `au` | Australia |
| `in` | India |

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

## Usage

### Claude Desktop

Add the following to your Claude Desktop configuration file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "checkpoint-waf": {
      "command": "uvx",
      "args": ["checkpoint-waf-mcp"],
      "env": {
        "CHECKPOINT_CLIENT_ID": "your-client-id",
        "CHECKPOINT_ACCESS_KEY": "your-access-key",
        "CHECKPOINT_REGION": "us"
      }
    }
  }
}
```

### Alternative: Running with pip

If you installed via pip, you can run the server directly:

```bash
python -m checkpoint_waf_mcp.server
```

### Example Prompts

Once connected, you can ask things like:

- "List all my WAF assets"
- "Show tuning suggestions for asset X"
- "Create a new web application asset for my API"
- "Publish my pending changes"

## API Reference

For more information about the Check Point WAF API, see the [Management API Reference](https://waf-doc.inext.checkpoint.com/references/management-api).

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
=======
# check-point-waf-mcp
>>>>>>> dc5633e3331693c183a1126be947ba898dca64ca
