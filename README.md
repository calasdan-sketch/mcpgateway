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
- **Read-only keys** — `readOnly: true` limits a key to tools whose server declared
  `readOnlyHint: true` (annotations are forwarded to clients and covered by pinning)
- **Keys that are safe to commit** — `keyHash` instead of `key`, `expiresAt`, `allowServers`;
  `mcpgateway hash-key --generate`
- **Ask the policy before you ship it** — `mcpgateway policy-test --tool x --args '{...}'`
- **Hardened by default at the edges** — rejected logins are audited and counted, the admin
  API checks `Host`, server stderr and tool names cannot inject terminal escapes

Drop-in: point your agent at the gateway instead of N servers — stdio (swap
the server command) or Streamable HTTP.

## Install

`mcpgateway` is **not on the npm registry yet** (a registry lookup for the name returned
"not found" on 2026-11-08). Until it is published, install from a checkout:

```bash
npm install && npm run build
npm pack                       # writes mcpgateway-<version>.tgz
npm install -g ./mcpgateway-*.tgz
mcpgateway --version
```

Requires Node ≥ 20. Maintained by Calas Automations Inc.

## Quickstart

```bash
mcpgateway init                       # writes ./mcpgateway.yaml (commented)
mcpgateway hash-key --generate        # prints a key for your client + a keyHash line
# edit mcpgateway.yaml: add your servers; replace the `key: "${GATEWAY_KEY}"` line
# with the keyHash line (no secret stays in the file; there is no default key)
mcpgateway validate -c mcpgateway.yaml
mcpgateway namespace -c mcpgateway.yaml   # preview the unified tool table
mcpgateway policy-test -c mcpgateway.yaml --tool github__search_code --args '{"q":"x"}'
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
| Tool annotations forwarded + read-only keys | **yes** | - | - | - | - | - |
| OpenTelemetry tracing | **no** | yes (per its README) | - | - | - | - |
| SSO / OAuth | **no** (bearer keys) | yes | yes | yes | yes | yes |
| Web UI | **no** | yes | yes | Docker Desktop | yes | - |
| Clustering / HA | **no** | yes | - | - | - | yes (K8s) |

Re-read on 2026-11-08 (their README text fetched read-only, none installed or run): ContextForge
advertises OpenTelemetry tracing, 40+ plugins and retry policies; Docker's gateway
advertises Docker Desktop secrets management. mcpgateway has none of those.

Where mcpgateway is the smaller tool: no SSO, no UI, no HA, no OpenTelemetry. Where it is
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
gateway pipeline), two runs on a noisy shared VM: direct p50 108 to 118 us, through the
gateway p50 239 to 280 us (about 130 to 160 us added for policy + rate limit + audit +
metrics). A 1,000,000-char tool result goes from about 9 ms direct to about 13 ms through
the gateway (the size guard serializes it once; response rules add little on top).
Audit throughput 66k to 133k records/s without the chain and 73k to 110k with it:
run-to-run noise on this VM is larger than the chain's cost, so this release makes no
claim about it. Numbers differ by 2x between runs; treat them as order of magnitude.

New in this release, same VM:

| `argRules` mode (3 deny patterns, microseconds per call) | ~100 B args | ~100 KB args |
|---|---|---|
| exact (default) | 1.9 to 2.6 us | 240 to 470 us |
| `ignoreCase` | 3.1 to 5.8 us | 450 to 710 us |
| `ignoreCase` + `normalizePaths` | 3.7 to 6.4 us | 680 to 1070 us |

Re-run on 2026-11-08 (round 5) on a busier VM, so everything is 2x to 4x slower than the runs above;
compare ratios only: direct p50 225 us, gateway 497 us (+272 us), gateway with the audit chain 573 us;
`argRules` exact 10 us (100 B) and 1.4 ms (100 KB); audit 17k to 27k records/s. New in round 5, the
argument depth guard: 0.1 us for ~100 B args and 53 us for ~100 KB args of mostly text (about 0.7 ms
for 128 KB made of 8,000 small objects, its worst shape). `npm run bench` prints it as section 6.

Credential-shape redaction (`audit.redactValues`) on 600-char string arguments: about
66k to 105k records/s off, 46k to 89k on. `bench/run.mjs` prints all of these.

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

An `argRules` pattern is tested against the JSON text of the arguments **and** against every
raw string value and key. (Earlier builds only saw the JSON text, where a backslash is written `\\`,
so a deny rule for `C:\Windows` never matched.) Matching is exact and case-sensitive unless
you opt in:

```yaml
policy:
  argMatch: { ignoreCase: true, normalizePaths: true }
```

`ignoreCase` also removes zero-width and bidi characters and folds full-width forms;
`normalizePaths` treats `\` as `/`, collapses `//`, `/./`, `/../` and decodes `%2e`-style
escapes (up to three layers). With both on, `/ETC//Passwd`, `/tmp/../etc/passwd`,
`%2fetc%2fpasswd` and `/etc/pa<zero-width>sswd` all hit a `/etc/passwd` deny. Substring
rules remain a tripwire, not a sandbox: a program can still build the forbidden path at
run time. Use `mcpgateway policy-test` to see a verdict without starting any server.

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

Further per-key options: `readOnly: true` (only tools whose server declared
`annotations.readOnlyHint: true`; no hint counts as not read-only, so it fails closed;
the hint is the server's own claim, which is why pinning covers annotations),
`allowServers: [globs]` (tools, resources **and** prompts of those servers only),
`expiresAt` (ISO 8601; checked on every request), and `keyHash: "sha256:<hex>"` in
place of `key` so the config never holds the secret (`mcpgateway hash-key`). Keys that
start with `changeme` are refused.

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

Also in the log: rejected HTTP requests (`auth_failed`: bad or expired key, missing scope,
wrong session key, bad Host; at most 30 records a minute, the rest are counted in
`mcpgateway_auth_failures_total`; the presented token is never written) and admin actions
(`admin:reload`, `admin:pins.accept`, with the key id). With `audit.redactValues` (default
true), credential shapes (`Bearer ...`, JWTs, `sk-...`, `AKIA...`, `ghp_...`, `xox?-...`,
PEM private-key headers, `scheme://user:password@`) are redacted from any string value and
from error messages, not only under secret-looking keys. That is a tripwire for common
formats, not a DLP engine. Control, bidi and zero-width characters inside records are
written as `\uXXXX` escapes (the record still parses to the same data, and `cat` cannot be
spoofed); the same characters are replaced in operator log lines.

Prometheus text on the admin port: `mcpgateway_tool_calls_total`,
`mcpgateway_tool_call_duration_seconds` (histogram), `mcpgateway_server_up`,
`mcpgateway_server_inflight`, `mcpgateway_policy_denials_total`,
`mcpgateway_rate_limit_hits_total`, `mcpgateway_audit_errors_total`, `mcpgateway_auth_failures_total{reason}`,
`mcpgateway_key_calls_total{key,status}` (key ids come from your config, so cardinality is bounded),
`mcpgateway_tool_calls_cancelled_total`.

### Admin API (default `http://127.0.0.1:3001`)

- `GET /healthz` — open (load-balancer convention): status, per-server up/circuit/inflight, audit
  errors. Downstream error text appears only for a caller with a valid key (it can echo secrets)
- `GET /metrics` — Prometheus exposition (`admin` scope)
- `GET /v1/registry` — servers, tool counts, health (any key)
- `GET /v1/namespace` — unified tool table + collision report (any key)
- `POST /v1/reload` — re-fetch all downstream catalogs (`admin` scope)
- `GET /v1/audit/head`, `GET /v1/pins`, `POST /v1/pins/accept` — see above (`admin` scope for head/accept)

The admin API **refuses to bind a public address** unless
`admin.allowPublicAdmin: true` is set explicitly. On a loopback bind it also rejects
foreign `Host` and `Origin` headers (DNS rebinding: a web page cannot drive `/v1/pins/accept`);
if you reach it through a proxy or tunnel with another host name, list it in
`admin.allowedHosts`.

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
mcpgateway policy-test --tool NAME [--args JSON] [--key ID] [-c config.yaml]
                                      # what would policy do with this call? (offline; exit 0 = allow, 1 = deny, 2 = bad config or usage)
mcpgateway hash-key [--generate | --key-env VAR]   # keyHash for the config (key from stdin by default)
mcpgateway audit-verify <audit.jsonl> [--key-env VAR]
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
  The admin API (`/healthz` is open) checks `Host`/`Origin` the same way.
- **Progress and logging notifications are not forwarded.** Client cancellation is (the
  downstream call is aborted and does not count against the circuit breaker), but a
  `progressToken` is not passed through and `notifications/message` from servers is dropped.
- **Read-only keys trust the server's own `readOnlyHint`.** Pinning catches a later flip,
  not a server that lied from the first day.
- **Catalogs are capped** at 200 pages / 20,000 entries per kind and server (a server that
  loops its cursor cannot trap the gateway). A failed refresh keeps the previous catalog.
- **JSON-RPC batches are capped at 100 messages** (413 above that). Tool-call arguments may nest
  at most 100 levels (refused with -32602 and audited as `args_too_deep`, never forwarded).
- **Slow clients are cut off:** request headers must arrive within 15 s and the whole request within 60 s.
- **stdio-only mode ends when the client closes stdin** (exit 0, children stopped); `SIGTERM`/`SIGINT` do the same
  in every mode. With the HTTP upstream also on, closing stdin does not stop the gateway.
- **Malformed JSON-RPC shapes** (for example `tools/call` without a `name`) get the MCP SDK's own
  validation error, which is a -32603 carrying the validator's text, not a tidy -32602. Not changed here.
- **A crashed server's in-flight call fails** (it is not retried); the server
  itself is reconnected with backoff (1s doubling to 30s).
- **No SSE resumability.** No event store: if a Streamable HTTP connection
  drops, clients reconnect and start a new session. Sessions are capped
  (`maxSessions`, default 128) so abandoned ones can't exhaust memory.
- **Wedged stdio children** get SIGTERM, then SIGKILL after 2 s. Not tested on Windows,
  where signals behave differently.
- **Windows is untested.** Path handling, `PATHEXT` lookup for `validate`, backslash
  commands and the `normalizePaths` rule are covered by unit tests of the logic only; no
  Windows machine was available. The pin file's `0600` mode has no effect on Windows.
- **Downstream error messages are scrubbed** of any secret values seen in the
  call's args (same redact-key list as the audit log), then truncated — but a
  server that leaks secrets through *other* channels (e.g. inside a returned
  document) is only caught if you configure `responseRedact` patterns.

## Development

```bash
npm install
npm test        # build + 168 tests (unit, in-process integration, real stdio crash recovery, HTTP)
npm run bench   # tools/list size, per-call latency, audit throughput
npm run lint    # tsc --noEmit (strict)
```

## License

MIT — see [LICENSE](LICENSE).
