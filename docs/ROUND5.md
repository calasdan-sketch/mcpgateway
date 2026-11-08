# Round 5 notes

Scope: author line, then a "first hour" packaging pass (the round-4 style, because `docs/ROUND4.md` did not
exist) and four field specialists. Branch `expert-2`. Registry upgrade test skipped on purpose: the name
`mcpgateway` is not on the npm registry (`npm view mcpgateway version` returned 404 on 2026-11-08), so there
is no older published version to upgrade from.

**How the specialists were run:** I could not spawn independent sub-agents in this session. One agent played the
four roles in sequence and ran real commands for each. They are not independent reviewers. Every finding below
names the command that proved it.

Scratch work lived in a temporary folder that was deleted at the end.

## Baseline (before any change)

- `npm test`: 153 tests, 153 pass, about 34 s.
- `node bench/run.mjs` on a busy shared VM: see README "Benchmark" for the re-run table. Numbers move 2x to 4x between runs.
- `npm pack --dry-run --json`: 137 files, 222 KB, including all of `dist/tests`, source maps, `src/` and `tests/`.
  `git ls-files` listed 2,507 files under `node_modules/` plus the whole `dist/`: both were committed.

## Author line

- `package.json` `author` is `Calas Automations Inc.` (it had none). `LICENSE` already said
  `Copyright (c) 2026 Calas Automations Inc.`. `--help` now ends "Maintained by Calas Automations Inc.".
- No old variants found: `grep -rniE "DC Enterprises|Dan Calas|calasdan" --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git .`
  leaves only the sibling-project link `github.com/calasdan-sketch/mcp-jail` in the README (a real GitHub URL, left alone).
- Removed the `(when published)` GitHub URL from `--help`. `package.json` has no `repository`, `homepage` or `bugs`
  field: the repo is private and no URL is claimed.
- No email added (none existed for this project).
- Pinned by `tests/round5.test.ts` ("author is exactly ...", "package.json is publish-shaped").
- Proof from the built tarball: `tar -xzOf mcpgateway-0.3.0.tgz package/package.json | grep author` prints
  `"author": "Calas Automations Inc."` and `package/LICENSE` line 3 matches.

## Specialist findings

| # | Specialist | Finding | Proving command | Status |
|---|---|---|---|---|
| 1 | AppSec reviewer | One valid key (even a read-only one) can open the circuit breaker for a whole downstream server: a tool-call argument nested 60,000 levels deep overflows the stack inside the call path, it is counted as a downstream failure, and after 12 such calls every caller gets "circuit breaker is open". | live gateway + `node deep.mjs` (12 deep calls, then a normal call) | FIXED: depth guard (100), -32602, audited `args_too_deep`, not forwarded. Test: "deeply nested arguments are refused ..." |
| 2 | MCP protocol author | Unknown or closed session id answers 400. The MCP Streamable HTTP session rules say 404 so a client knows to re-initialize. (From my knowledge of the 2025-06-18 spec; I did not re-fetch it in this session.) | `DELETE /mcp` then `POST /mcp` with the same id, in `probe.mjs` | FIXED: 404 for POST, GET, DELETE. Test: "unknown or closed session id answers 404 ..." |
| 3 | API gateway / AuthZ engineer | `Authorization: bearer <key>` (lower case scheme) is rejected 401. RFC 7235 section 2.1 says the scheme is case-insensitive; some clients send lower case. | `probe.mjs` "lowercase bearer" | FIXED on MCP and admin endpoints. Test: "lowercase bearer authenticates ..." |
| 4 | SRE | In stdio-only mode the gateway keeps running after the client closes stdin: it holds admin port 3001 and every child server (a second copy then fails with EADDRINUSE). | `node stdio.mjs eof` printed "STILL RUNNING after 8s" | FIXED for stdio-only; deliberately NOT for stdio+HTTP (a supervisor without stdin is normal there; a second test pins that). |
| 5 | SRE | No slow-client deadlines beyond Node defaults (headers 60 s, request 5 min). | read of `listenHttp` / `startAdmin` | FIXED: 15 s / 60 s. Test asserts the values. Not exercised with a real slow-loris client. |
| 6 | First-hour user | `mcpgateway serve -c` (flag with no value) prints "cannot read config file undefined: The path argument must be of type string". | `mcpgateway serve -c; echo $?` from the installed tarball | FIXED: "flag -c needs a value", exit 2. |
| 7 | CI integrator | `policy-test` exits 1 for DENY and also 1 for an unreadable or invalid config; CI cannot tell them apart. | `mcpgateway policy-test -c bad.yaml --tool x; echo $?` | FIXED: invalid config exits 2. README documents 0/1/2. |
| 8 | Release engineer | `npm pack` shipped tests, fixtures, maps and `src/`; no `files` list; no author or keywords; `node_modules/` and `dist/` tracked in git. | `npm pack --dry-run --json` (137 files before, 34 after) | FIXED: `files` whitelist, `.gitignore`, `git rm --cached node_modules dist`. The old objects stay in git history, so a bundle of the whole branch is still large. |
| 9 | Windows reviewer (static) | A server `command` written with backslashes (`C:\tools\srv.exe`) was treated as a bare name and searched on PATH, so `validate` said "not found". | read of `config.ts` + unit test | FIXED (logic only; never run on Windows). Other static notes below. |
| 10 | MCP protocol author | `tools/call` with no `name` returns -32603 with the validator's JSON dump, and a valid JSON body that is not JSON-RPC gets -32700 with a dump. Both come from the MCP SDK's own validation (version 1.17.0). | `probe.mjs` "call no name", "big body 5MB" | NOT DONE: harmless text, SDK behaviour; documented in README limits. |
| 11 | AuthZ engineer | Checked and fine: key ACL and readOnly apply through the `gateway_call_tool` meta-tool; per-key rate budget applies to resources and prompts too; cross-key session reuse is 403; Host/Origin checks apply to the admin API; query-string keys are rejected. | `probe.mjs`, read of `handleResourceRead` | no change |
| 12 | AuthZ engineer | Fleet `denyTools` and `argRules` do not apply to resource URIs or prompt names/arguments (v1 scope, already in the file header). A budget refusal on `resources/read` is not audited (tools are). | read of `handleResourceRead` | NOT DONE (idea table) |

Static Windows notes (nothing was run on Windows): audit rotation uses `renameSync` on a file that is
opened and closed per write, so it only fails if another program holds the file open without delete sharing;
the pin file's `0600` mode is ignored on Windows; `SIGTERM` is not delivered to Windows console programs, so
the stdin-close shutdown above is the useful path there; `.cmd` launchers (`npx`) depend on the MCP SDK's
spawn handling and are unverified; no `shell: true` anywhere (`grep -n shell src/*.ts` only hits comments).

## Quality methods used this round

- **Differential / property test:** `exceedsDepth` is compared with a plain recursive reference on 300 seeded
  random structures and random limits; plus a 100,000-deep input that would crash a recursive walker.
- **Mutation-style sanity** (flip one condition, rebuild, run `dist/tests/round5.test.js`, restore):
  `depth > max` -> `depth > max + 1000` (2 tests failed); case-insensitive flag removed from the Bearer regex
  (2 failed); 404 -> 400 for unknown session (1 failed); depth guard disabled (1 failed); missing-value check in
  the CLI removed (killed: the test run hung, which is a failure). Sources were restored byte for byte (`cmp`).
- **Golden files:** none added. Existing tests already pin the audit chain and metrics text; I did not add new
  golden files for output formats (see idea table).
- **Hostile input, live:** invalid JSON, empty/truncated bodies, `[1,"a",null]`, empty batch, array arguments,
  `__proto__` keys, 60,000- and 1,000,000-deep arguments, 5 MB body, wrong protocol-version header, non-ASCII
  Authorization header, PUT/OPTIONS: all answered without a crash; gateway stayed up.

## Idea table

Scores 1 (low) to 5 (high); effort and risk: lower is better.

| # | Idea | User value | Differentiation | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Argument depth guard | 5 | 2 | 1 | 1 | DONE |
| 2 | 404 for unknown sessions | 4 | 1 | 1 | 1 | DONE |
| 3 | Case-insensitive Bearer | 3 | 1 | 1 | 1 | DONE |
| 4 | stdio-only shutdown on stdin close | 4 | 1 | 1 | 2 | DONE |
| 5 | Slow-client timeouts | 3 | 1 | 1 | 1 | DONE |
| 6 | CLI missing-value errors | 3 | 1 | 1 | 1 | DONE |
| 7 | policy-test exit code 2 for bad config | 3 | 1 | 1 | 1 | DONE |
| 8 | npm `files` whitelist, untrack node_modules/dist | 5 | 1 | 1 | 1 | DONE |
| 9 | Windows backslash commands | 2 | 1 | 1 | 1 | DONE (unrun) |
| 10 | Property/differential tests for the depth checker | 3 | 1 | 2 | 1 | DONE |
| 11 | Author pin + version-consistency tests | 3 | 1 | 1 | 1 | DONE |
| 12 | Tidy -32602 for malformed `tools/call` shapes (wrap SDK validation) | 2 | 2 | 3 | 3 | NOT-DONE |
| 13 | Apply `denyTools`/`argRules` to resource URIs and prompt arguments | 4 | 4 | 4 | 3 | NOT-DONE |
| 14 | Audit budget-refused `resources/read` and `prompts/get` | 2 | 2 | 2 | 1 | NOT-DONE |
| 15 | OpenTelemetry tracing (competitor feature) | 4 | 1 | 5 | 3 | NOT-DONE |
| 16 | OAuth 2.1 / SSO at the edge (MCP authorization spec) | 5 | 1 | 5 | 4 | NOT-DONE |
| 17 | Hot-reload of key list on SIGHUP (without dropping sessions) | 3 | 2 | 3 | 3 | NOT-DONE |
| 18 | `/readyz` that reports downstream health separately from `/healthz` | 3 | 2 | 2 | 1 | NOT-DONE |
| 19 | Golden-file tests for `namespace`, `policy-test`, `audit-verify` output | 2 | 1 | 2 | 1 | NOT-DONE |
| 20 | Windows CI run (never tested on Windows) | 4 | 1 | 3 | 1 | NOT-DONE (needs a Windows runner) |
| 21 | Forward `progress` and server log notifications | 3 | 3 | 4 | 3 | NOT-DONE |
| 22 | Per-key arg-size and result-size limits | 3 | 3 | 3 | 2 | NOT-DONE |
| 23 | SIEM-ready audit export (CEF / OTLP logs) | 3 | 2 | 4 | 2 | NOT-DONE |
| 24 | Per-key session cap exposed in config (currently half of `maxSessions`) | 2 | 1 | 1 | 1 | NOT-DONE |

## Competitors (read-only, README text only, 2026-11-08)

Fetched the READMEs of IBM/mcp-context-forge and docker/mcp-gateway and counted keywords. ContextForge mentions
OpenTelemetry, RBAC, SSO, rate limits and Prometheus; Docker's gateway mentions OAuth and secrets handling. That matches the
README comparison table; nothing was installed or run, so feature claims stay "per their README".

## What I could not test

- Windows, macOS: never run. Node 22.23 on Linux only; the declared minimum (Node 20) was not run.
- A real slow-loris client against the new timeouts; only the configured values are asserted.
- Upgrade from a registry version: none exists.
- A real MCP client (Claude Desktop, Inspector) against the gateway. All protocol checks used curl, a Node script
  and the in-repo SDK client.
- Registry name availability beyond one `npm view` 404; the name could still be taken by the time of upload.
