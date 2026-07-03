# Phantom Vault MCP Protocol

## Overview

Phantom Vault implements the Model Context Protocol (MCP) to integrate with AI assistants like Claude Code. This document specifies the available tools and their interfaces.

## Connection

### Unix Socket (Recommended)

```
~/.phantom-vault/mcp.sock
```

### TCP

```
localhost:9999
```

## Protocol

Standard JSON-RPC 2.0 over the transport.

## Initialization

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "client_info": {
      "name": "Claude Code",
      "version": "1.0.0"
    }
  },
  "id": 1
}
```

### Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "protocol_version": "1.0",
    "capabilities": {
      "tools": true,
      "lineage_tracking": true
    }
  },
  "id": 1
}
```

## Tools

### vault_list

List available secret names in the vault.

#### Input Schema

```json
{
  "type": "object",
  "properties": {
    "namespace": {
      "type": "string",
      "description": "Namespace to list (default: 'default')"
    },
    "include_metadata": {
      "type": "boolean",
      "description": "Include metadata like creation time"
    }
  }
}
```

#### Output

```json
{
  "secrets": [
    {
      "name": "API_KEY",
      "namespace": "default",
      "created_at": "2024-01-15T10:30:00Z",
      "is_canary": false
    }
  ]
}
```

### vault_run

Execute a command with secrets injected as environment variables.

#### Input Schema

```json
{
  "type": "object",
  "properties": {
    "command": {
      "type": "string",
      "description": "Command to execute"
    },
    "args": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Command arguments"
    },
    "secrets": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name": { "type": "string" },
          "env_var": { "type": "string" }
        }
      },
      "description": "Secrets to inject"
    },
    "timeout": {
      "type": "integer",
      "description": "Timeout in seconds"
    }
  },
  "required": ["command", "secrets"]
}
```

#### Output

```json
{
  "exit_code": 0,
  "stdout": "Success\n",
  "stderr": "",
  "sanitized": true,
  "execution_ms": 150
}
```

#### Security Notes

- Output is automatically sanitized
- Commands are pre-analyzed for oracle patterns
- Execution happens in a sandbox

### vault_exists

Check if specific secrets exist.

#### Input Schema

```json
{
  "type": "object",
  "properties": {
    "names": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Secret names to check"
    },
    "namespace": {
      "type": "string"
    }
  },
  "required": ["names"]
}
```

#### Output

```json
{
  "exists": {
    "API_KEY": true,
    "DB_PASSWORD": false
  }
}
```

### vault_audit

Query the audit log.

#### Input Schema

```json
{
  "type": "object",
  "properties": {
    "limit": {
      "type": "integer",
      "description": "Maximum entries to return"
    },
    "secret_name": {
      "type": "string",
      "description": "Filter by secret name"
    },
    "event_type": {
      "type": "string",
      "enum": ["read", "write", "delete", "rotate"]
    },
    "since": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

#### Output

```json
{
  "entries": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "event_type": "read",
      "secret_name": "API_KEY",
      "lineage_id": "abc123"
    }
  ],
  "total": 1
}
```

## Lineage Tracking

Every request includes a lineage ID that tracks the request chain.

### Headers

```json
{
  "X-Lineage-ID": "parent-lineage-id"
}
```

The server generates a new lineage ID for each request and records the parent relationship.

## Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32600 | Invalid Request | Malformed JSON-RPC |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid parameters |
| 1001 | Vault sealed | Vault is not open |
| 1002 | Secret not found | Requested secret doesn't exist |
| 1003 | Command blocked | Command failed pre-analysis |
| 1004 | Timeout | Command execution timed out |
| 1005 | Sanitization failed | Could not sanitize output |

## Claude Code Configuration

Add to `~/.claude/mcp.json`:

```json
{
  "servers": {
    "phantom-vault": {
      "command": "phantom-vault",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```
