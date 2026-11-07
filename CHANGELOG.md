# Changelog

## 0.3.0 (unreleased)

Expert review round (MCP platform, proxy performance, security, enterprise admin, agent developer).

### Round 3 (additions to this unreleased line)

Specialists: MCP protocol engineer, red-team attacker, compliance auditor, production SRE,
performance engineer, README-only newcomer, competitor engineer.

#### Fixed
- **Only the first page of `tools/list`, `resources/list` and `prompts/list` was read.** A server
  with more than one page lost every tool after it. Pages are followed now (bounded: 200 pages,
  20,000 entries, a repeated cursor ends the walk). A failed refresh used to *empty* a server's
  catalog; it now keeps the previous one.
- **A POST with an empty, truncated or NUL body hung the connection forever** (the 400 path never
  answered). Oversized JSON-RPC batches took quadratic time (5,000 pings = 4 s); batches are capped at 100 (413).
- **A deny rule containing a backslash never matched** (`C:\Windows`): rules only saw the JSON text,
  where backslashes are doubled. Rules now also see every raw string value and key.
- Client cancellation was not forwarded: the downstream call kept running and a queued call kept
  its place. Now the call is aborted downstream and does not count against the breaker.
- Rejected logins (`auth_failed`) were never audited. Admin reloads and pin accepts were not audited.
- Tool names, server error text and child stderr were written raw to the terminal and audit file;
  escape sequences and bidi overrides could repaint the operator's screen. Neutralized.
- `validate` could not find `npx` on Windows (`PATHEXT`).
- A server whose stderr filled the pipe could stall; stderr is now always drained (sanitized, rate-limited).

#### Added
- Tool `annotations`, `title` and `outputSchema` are forwarded and covered by pinning.
  Old pin files upgrade once, silently, then the file is rewritten as version 2.
- Per-key `readOnly`, `allowServers` (also gates resources and prompts, which per-key ACLs missed),
  `expiresAt`, `keyHash`; `mcpgateway hash-key`.
- `policy.argMatch` (`ignoreCase`, `normalizePaths`); `mcpgateway policy-test`.
- `audit.redactValues` (default on): credential shapes redacted from any value and from errors.
- Admin: Host/Origin check, `admin.allowedHosts`, anonymous `/healthz` without error text.
- Metrics `mcpgateway_auth_failures_total`, `mcpgateway_key_calls_total`, `mcpgateway_tool_calls_cancelled_total`.
- SIGKILL 2 s after SIGTERM for stdio children on shutdown.

#### Changed (behavior)
- **The example config no longer has a default key.** `${GATEWAY_KEY}` unset is a startup error
  (it used to fall back to a published placeholder). Keys starting with `changeme` are refused.
  Use `keyHash` to avoid needing the variable at all.
- Admin API on a loopback bind rejects a foreign `Host`/`Origin` (add `admin.allowedHosts` for a proxy/tunnel).
- Anonymous `/healthz` no longer includes `lastPingOk`/`lastError`; send a valid key to get them.
- Credential shapes in audit args/errors are redacted by default (`audit.redactValues: false` to opt out).
- Rules in `argRules` now also match raw string values: a rule that matched nothing before
  (backslashes) may start denying. `allow` rules can likewise start passing calls they refused.

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
