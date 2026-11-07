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
- **Search exposure** (`exposure.mode: search`) — agents see 2 meta-tools instead
  of hundreds of tool schemas: 7x to 170x fewer tokens in `tools/list` (see benchmark)
- **Rug-pull defense** — tools are pinned by hash of description + schema; a
  changed tool is flagged or quarantined until you accept it
- **Per-key tool access and rate budgets** — a key can be limited to
  `github__search_*` and capped at its own rps, so one noisy agent cannot starve the rest
- **Self-healing** — a crashed stdio server is restarted with backoff; client
  mistakes no longer trip the circuit breaker
- **Tamper-evident audit** (`audit.chain: true`) — hash-chained JSONL, `mcpgateway audit-verify`

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

## Compared with other gateways

Based on each project's README as of this writing; **none of these were installed
or run for this table** (unverified beyond their docs). "-" means the README does
not mention it, not that it is absent. Corrections welcome.

| | mcpgateway | [IBM ContextForge](https://github.com/IBM/mcp-context-forge) | [MetaMCP](https://github.com/metatool-ai/metamcp) | [Docker MCP Gateway](https://github.com/docker/mcp-gateway) | [mcphub](https://github.com/samanhappy/mcphub) | [Microsoft mcp-gateway](https://github.com/microsoft/mcp-gateway) |
|---|---|---|---|---|---|---|
| Runtime / footprint | one Node process, 2 deps, no database | service + DB (see its docs) | Docker stack with DB | Docker CLI plugin, containerized servers | Node service | Kubernetes / Azure |
| Fleet policy (allow/deny/arg/egress) | yes | plugin framework | middleware | plugins | - | - |
| Per-key tool ACL | yes | RBAC / teams | API keys + endpoints | - | per-user | RBAC |
| Per-key rate budget | yes | rate-limit policies | yes (per user+endpoint) | - | - | - |
| Tool pinning (rug-pull) | **yes** | - | - | - | - | - |
| Tool search / context saver | keyword, local | - | - | - | vector "smart routing" | - |
| Tamper-evident audit | **hash chain + verifier** | audit trail | - | - | audit (basic) | - |
| Prometheus | yes | yes (+ OpenTelemetry) | - | - | - | - |
| SSO / OAuth | **no** (bearer keys) | yes | yes | yes | yes | yes |
| Web UI | **no** | yes | yes | Docker Desktop | yes | - |
| Clustering / HA | **no** | yes | - | - | - | yes (K8s) |

Where mcpgateway is the smaller tool: no SSO, no UI, no HA. Where it is
ahead: a single dependency-light process you can read in an afternoon, plus the
supply-chain and audit controls above.

## Benchmark (re-run it: `npm run bench`)

Measured on a small shared Linux VM with this repo's own stdio fixture; absolute
times vary by machine, the ratios are the point. Token counts are chars/4
estimates, not a tokenizer.

| tools behind the gateway | `tools/list` full | search mode | reduction |
|---|---|---|---|
| 23 | ~1,430 tokens | ~195 | 7x |
| 103 | ~6,700 | ~195 | 34x |
| 503 | ~33,300 | ~195 | 170x |

Per-call latency (sequential, in-memory upstream so the number isolates the
gateway pipeline): direct p50 111 us, through the gateway p50 288 us (about
180 us added for policy + rate limit + audit + metrics). A 1,000,000-char tool
result adds about 4 ms through the gateway when no response rules are set
(down from about 7 ms in 0.2.0, which serialized and walked it for nothing).
The audit hash chain costs about a quarter of raw audit write throughput
(121k to 89k records/s) and is invisible next to a real tool call.

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

### Rug-pull defense (tool pinning)

An MCP server controls its own tool descriptions, and the model reads them as
instructions. A server you approved can change a description later. With
`policy.pinning`, the gateway hashes each tool's description + input schema the
first time it sees it and compares on every catalog refresh:

- `warn` — log, audit record, `mcpgateway_tool_pin_violations_total`; tool still served
- `block` — the changed tool disappears from `tools/list` and calls fail as
  "unknown tool" until an operator reviews it and runs
  `POST /v1/pins/accept?tool=<server>:<tool>` (admin scope; omit `tool` to accept all)

`block` requires a pin file, and a corrupt pin file is a startup error. Separately,
control, bidi-override and zero-width characters are replaced in every description
and schema string, and descriptions that look instruction-like (`<IMPORTANT>`
tags, "ignore previous instructions", credential-file paths) produce a warning.
That heuristic is a tripwire, not a guarantee; pinning is the control.

### Per-key access

```yaml
auth:
  keys:
    - id: support-bot
      key: "${SUPPORT_KEY}"
      scopes: [tools:call, tools:list]
      allowTools: ["zendesk__*", "kb__search"]
      rateLimit: { rps: 5, burst: 10 }
```

Tools a key may not use are removed from its `tools/list` and answer "unknown
tool" (same masking as `hideTools`). Sessions belong to the key that opened them.
Typos in `policy`, `auth` or `exposure` are now startup errors instead of silently
ignored rules.

### Search exposure

`exposure.mode: search` lists only `gateway_search_tools` and `gateway_call_tool`
(plus anything in `alwaysExpose`). The agent searches by keyword, gets names +
schemas, then calls through the meta-tool. Policy, per-key ACLs, rate limits and
audit see the real tool name. Direct calls to a known tool name still work. Search
is keyword scoring over name and description; there is no embedding model.

### Audit & metrics

One JSONL record per call: timestamp, request id, session, key id, tool,
server, original tool name, duration, status, error. Argument values whose key
looks secret (`token`, `secret`, `password`, … — configurable, substring,
case-insensitive, recursive) become `[REDACTED]`; serialized args are capped
(8KB default, visible truncation marker); set `logArgs: false` to store only a
SHA-256 of the args. Size-based rotation with a bounded file count — the log
can never fill the disk. With `audit.chain: true` every record carries `seq`,
`prev` and `hash`; `mcpgateway audit-verify audit.jsonl [--key-env VAR]` checks
the chain across rotated files and detects edited, inserted, removed or reordered
records. It cannot see truncation of the newest records by itself: store
`GET /v1/audit/head` somewhere the gateway host cannot write, and compare. Add
`audit.chainKey` (HMAC) so someone who can rewrite the file cannot also recompute
the hashes. The writer never throws into the request path;
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
- `POST /v1/reload` — re-fetch all downstream catalogs (`admin` scope)
- `GET /v1/audit/head`, `GET /v1/pins`, `POST /v1/pins/accept` — see above (`admin` scope for head/accept)

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
- **Host/Origin checks need configuration off loopback.** Loopback binds reject
  foreign `Host` and `Origin` headers by default (DNS-rebinding defense). A public
  bind is unchecked until you set `upstream.http.allowedHosts`/`allowedOrigins`.
  The admin API (`/healthz` is open) does not do this check yet.
- **Tool annotations and output schemas are not forwarded** — only name,
  description and input schema.
- **A crashed server's in-flight call fails** (it is not retried); the server
  itself is reconnected with backoff (1s doubling to 30s).
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
npm test        # build + 114 tests (unit, in-process integration, real stdio crash recovery, HTTP)
npm run bench   # tools/list size, per-call latency, audit throughput
npm run lint    # tsc --noEmit (strict)
```

## License

MIT — see [LICENSE](LICENSE).
