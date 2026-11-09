# Changelog

## 0.2.0 - 2026-11-08

First release on npm.

- `mcpgateway` command that sits in front of several MCP servers and exposes them as one tool namespace.
- Policy and per-key tool allowlists (`auth.keys[].tools`), per-tool rate limits, an audit log and Prometheus metrics.
- Tool-definition pinning with warn and quarantine modes; flags invisible characters in tool metadata.
- `mcpgateway import` converts a `.mcp.json` file into a servers block.
