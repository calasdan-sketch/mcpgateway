# Changelog

## 0.3.0 (unreleased)

Expert review round (MCP platform, proxy performance, security, enterprise admin, agent developer).

### Fixed (bugs found by testing 0.2.0)
- Any key with `tools:call` could trip a server's circuit breaker for everyone with five
  malformed calls: server answers `InvalidParams`/`MethodNotFound` now count as success.
- A crashed stdio server stayed dead until the gateway restarted. It is now reconnected
  with capped exponential backoff (`mcpgateway_server_reconnects_total`).
- `POST /v1/reload` only rebuilt from cached catalogs; it now re-fetches from the servers.
- `mcpgateway_server_up` was set once at startup and never changed; it now tracks live health.
- A POST body of JSON `null` left the HTTP request hanging forever; batch elements that were
  not objects caused a 500. Both are 400 now.
- Egress rules (`responseRedact/Block/Warn`) did not apply to resource reads or prompts. They do now.
- Error messages carried a doubled `MCP error -32000: MCP error -32000:` prefix.
- Audit test no longer fails when run as root or when a directory it assumed absent exists.

### Added
- `exposure.mode: search` (context-window saver), `alwaysExpose`.
- `policy.pinning` (warn | block), pin file, `/v1/pins`, `/v1/pins/accept`; description sanitizing
  of control/bidi/zero-width characters; instruction-like description warnings.
- Per-key `allowTools`, `denyTools`, `rateLimit`; sessions bound to the opening key; idle
  session expiry and a per-key session cap.
- Host/Origin validation for the HTTP upstream (`allowedHosts`, `allowedOrigins`).
- `audit.chain`, `audit.chainKey`, `mcpgateway audit-verify`, `GET /v1/audit/head`.
- `npm run bench` and `bench/run.mjs`.

### Changed (behavior)
- Unknown keys inside `policy`, `auth`, `auth.keys[]` and `exposure` are now **errors**
  (a typo used to silently disable a rule). Other sections warn.
- Bearer keys are compared via SHA-256 digests so key length does not leak.
- Response scanning is skipped entirely when no response rules are configured.
- HTTP requests with a foreign `Host`/`Origin` header on a loopback bind get 403.
