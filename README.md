# mcpgateway

One process fronting all your MCP servers. MCP works in demos; production is a
mess — dozens of tools across servers, duplicated config, fragmented audit
logs, tool name collisions, no fleet-wide policy, zero visibility into what
gets called. `mcpgateway` is the missing production layer:

- **Unified tool namespace** — one `tools/list` across all servers, with
  collision resolution (`prefix` default, `priority`, `explicit`)
- **Fleet-wide policy** — allow/deny/hide, argument substring rules, response
  redact/block/warn, observe mode (mcp-jail semantics, fleet scope)
- **Per-tool rate limits** — token buckets, bounded memory
- **Centralized audit log** — append-only JSONL, secret redaction, rotation
- **Prometheus metrics** — per-tool calls, latency histograms, server health
- **Auth at the edge** — bearer keys with scopes; the gateway holds downstream
  credentials (no more per-server secret sprawl)
- **Curated discovery** — `mcpgateway namespace` previews the unified table;
  `/v1/registry` and `/v1/namespace` on the admin API

Drop-in: point your agent at the gateway instead of N servers — stdio (swap
the server command) or Streamable HTTP.

## Install

```bash
npm install -g mcpgateway
# or run from source:
npm install && npm run build && node dist/src/index.js --help
```

Requires Node ≥ 20.

## Quickstart

```bash
mcpgateway init                    # writes ./mcpgateway.yaml (commented)
# edit mcpgateway.yaml: add your servers, set GATEWAY_KEY
mcpgateway validate -c mcpgateway.yaml
mcpgateway namespace -c mcpgateway.yaml   # preview the unified tool table
mcpgateway serve -c mcpgateway.yaml
```

Point your agent at it (stdio drop-in):

```json
{
  "mcpServers": {
    "gateway": { "command": "mcpgateway", "args": ["serve", "-c", "/path/to/mcpgateway.yaml"] }
  }
}
```

Or serve Streamable HTTP (`upstream.http.enabled: true` in config, or the
`--http` flag: `mcpgateway serve -c mcpgateway.yaml --http`) and point remote
agents at `http://host:3000/mcp` with a bearer key.

## How it works

```
agent ──stdio / Streamable HTTP──▶ mcpgateway ──┬──stdio──▶ server A
   (one session)      auth at edge │              ├──stdio──▶ server B
   unified namespace  policy engine│              └──http───▶ server C
   rate limits        audit+metrics│
```

Each downstream server gets an independent MCP session with bounded
concurrency (stdio defaults to 1 — most stdio servers are single-threaded),
per-call timeouts, a circuit breaker (5 consecutive failures → 30s open, fail
fast, half-open ping probe), and periodic health checks. Catalog changes
(`tools/list_changed`) rebuild the unified namespace without dropping
in-flight calls.

### Namespace & collisions

MCP tool names must match `^[a-zA-Z0-9_-]{1,64}$`. When two servers expose the
same tool name:

| strategy | behavior |
|---|---|
| `prefix` (default) | `compare` on `github` → `github__compare`. Deterministic, no silent shadowing. |
| `priority` | highest-priority server keeps the bare name; losers are prefixed (still reachable). Every shadowing is logged. |
| `explicit` | `mappings: {"compare": "github"}` picks the winner; unmapped collisions are a **startup error**. |

Non-colliding tools keep their bare names. Aliases (`{"server:tool": "name"}`)
override anything. A renamed tool longer than 64 chars, or a public name that
collides with another tool's natural name, is a hard error with a suggested
fix — run `mcpgateway namespace` to preview before serving.

### Policy (fleet scope)

`policy.allowTools` / `denyTools` / `hideTools` are glob patterns over public
tool names (`*` supported); **deny wins**, hidden tools vanish from listings
*and* are denied on call — the caller sees the same `unknown tool` error as
for unmapped names, so probing can't confirm a hidden tool exists (the audit
record keeps the real `hidden` reason for operators). `argRules` are
**substring** matchers over the JSON-encoded arguments (deliberately not
regex — no ReDoS). `responseRedact` / `responseBlock` / `responseWarn` scan
the JSON-encoded result (first 64KB). `mode: observe` logs would-be verdicts
and forwards everything — safe onboarding.

This is the **fleet** layer. For per-server deep policy (argument shapes,
human approvals), pair it with
[mcp-jail](https://github.com/calasdan-sketch/mcp-jail): gateway decides
*which* tools exist and *who* may call them; the jail decides *how* each
server's tools may be used.

### Audit & metrics

One JSONL record per call: timestamp, request id, session, key id, tool,
server, original tool name, duration, status, error. Argument values whose key
looks secret (`token`, `secret`, `password`, … — configurable, substring,
case-insensitive, recursive) become `[REDACTED]`; serialized args are capped
(8KB default, visible truncation marker); set `logArgs: false` to store only a
SHA-256 of the args. Size-based rotation with a bounded file count — the log
can never fill the disk. The writer never throws into the request path;
failures are counted and surfaced on `/healthz`.

Prometheus text on the admin port: `mcpgateway_tool_calls_total`,
`mcpgateway_tool_call_duration_seconds` (histogram), `mcpgateway_server_up`,
`mcpgateway_server_inflight`, `mcpgateway_policy_denials_total`,
`mcpgateway_rate_limit_hits_total`, `mcpgateway_audit_errors_total`.

### Admin API (default `http://127.0.0.1:3001`)

- `GET /healthz` — open (load-balancer convention): status, per-server health, audit errors
- `GET /metrics` — Prometheus exposition (`admin` scope)
- `GET /v1/registry` — servers, tool counts, health (any key)
- `GET /v1/namespace` — unified tool table + collision report (any key)
- `POST /v1/reload` — refresh all downstream catalogs (`admin` scope)

The admin API **refuses to bind a public address** unless
`admin.allowPublicAdmin: true` is set explicitly.

## Configuration

See [`mcpgateway.example.yaml`](mcpgateway.example.yaml) — every option is
commented. Highlights:

- `${VAR}` / `${VAR:-default}` env interpolation everywhere (unset without a
  default = startup error naming the variable)
- stdio servers spawn with `shell: false` and an argv array; env is a small
  safe-default set plus your `env` block
- bearer keys carry scopes: `tools:call`, `tools:list`, `resources:*`,
  `prompts:*`, `admin` (compared in constant time)
- the config file is **trusted operator input** (like `sshd_config`) — `chmod 600`

## CLI

```
mcpgateway serve [-c config.yaml]     # stdio upstream by default; logs to stderr
mcpgateway validate [-c config.yaml]  # config checks; --network adds reachability
mcpgateway namespace [-c config.yaml] # connect + print the unified tool table
mcpgateway init [-o out.yaml]         # write the starter config
```

## Limitations (honest)

- **No sampling/elicitation proxying.** If a downstream server initiates
  `sampling/createMessage` or `elicitation/create`, the gateway answers
  "method not found". Forwarding server→client requests across two
  independent sessions is a correctness swamp we chose not to wade into for v1.
- **No roots.** The gateway advertises an empty roots list downstream.
- **Prefix-on-collision only.** Non-colliding tools keep bare names, so adding
  a server later *can* rename a previously bare tool (it becomes prefixed).
  Pin names you depend on with `aliases`.
- **Single process.** No clustering or HA in v1; run one gateway per host and
  put it behind your own supervisor. In-flight calls are capped
  (`globalMaxInflight`, default 256) so the gateway degrades loudly, not
  silently.
- **Config is trusted.** A malicious config file owns the machine (it names
  commands to spawn). This is by design — like `sshd_config` — but don't
  generate configs from untrusted input.
- **HTTP URLs are operator-trusted.** Server `url`s are called as configured;
  the gateway does not SSRF-filter them (your servers usually *are*
  localhost). Don't point it at URLs you don't control.
- **No request/response transformation.** The gateway routes, guards, and
  observes; it does not rewrite payloads. No result caching either.
- **Audit is local JSONL.** Rotation is bounded, but shipping to a SIEM is
  your job (filebeat/vector sidecar).
- **Metrics are Prometheus-text only.** No OTel exporter in v1.
- **HTTP upstream has no CSRF/DNS-rebinding hardening** beyond bearer auth —
  bind it to localhost or put it behind your own reverse proxy with origin
  checks for browser-adjacent use.
- **No SSE resumability.** No event store: if a Streamable HTTP connection
  drops, clients reconnect and start a new session. Sessions are capped
  (`maxSessions`, default 128) so abandoned ones can't exhaust memory.
- **Wedged stdio children are SIGTERM'd, not SIGKILL'd,** on gateway shutdown;
  a child that ignores SIGTERM will linger as an orphan.
- **Downstream error messages are scrubbed** of any secret values seen in the
  call's args (same redact-key list as the audit log), then truncated — but a
  server that leaks secrets through *other* channels (e.g. inside a returned
  document) is only caught if you configure `responseRedact` patterns.

## Development

```bash
npm install
npm test        # build + 77 tests (unit + in-process integration)
npm run lint    # tsc --noEmit (strict)
```

## License

MIT — see [LICENSE](LICENSE).
