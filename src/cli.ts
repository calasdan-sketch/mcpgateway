/**
 * CLI: serve | validate | namespace | init
 *
 * In stdio upstream mode, stdout is the MCP channel — ALL operational logging
 * goes to stderr.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConfigError, configWarnings, loadConfigFile } from './config.js';
import { startGateway } from './gateway.js';
import { buildNamespace } from './namespace.js';
import { DownstreamServer } from './downstream.js';
import { verifyChain } from './audit.js';
import { randomBytes } from 'node:crypto';
import { checkToolCall, isHidden } from './policy.js';
import { globMatch, hashKey } from './util.js';
import { VERSION } from './version.js';

const HELP = `mcpgateway ${VERSION} — one process fronting all your MCP servers.

Usage:
  mcpgateway serve [-c config.yaml]     Serve the unified gateway (stdio upstream by default)
  mcpgateway serve --http [-c config]  Also serve Streamable HTTP upstream (uses upstream.http.* settings)
  mcpgateway validate [-c config.yaml]  Validate config (add --network for reachability checks)
  mcpgateway namespace [-c config.yaml] Connect and print the unified tool table
  mcpgateway init [-o out.yaml]         Write a commented starter config
  mcpgateway audit-verify <audit.jsonl> [--key-env VAR]
                                        Verify the audit hash chain (includes rotated .N files)
  mcpgateway policy-test --tool NAME [--args JSON] [--key ID] [-c config.yaml]
                                        Ask the policy what it would do with a call (offline; no servers started)
  mcpgateway hash-key [--generate | --key-env VAR]
                                        Print a sha256 keyHash for the config (key from stdin, env, or freshly generated)
  mcpgateway --version | --help

Options:
  -c, --config <path>   Config file (default: ./mcpgateway.yaml)
  --http                serve: enable the Streamable HTTP upstream too
  --network             validate/namespace: check server reachability (validate skips by default)
  -o, --output <path>   init: output path (default: ./mcpgateway.yaml)
  -f, --force           init: overwrite existing file

Docs: https://github.com/calasdan-sketch/mcpgateway (when published)
`;

interface Args {
  command: string;
  config: string;
  network: boolean;
  http: boolean;
  output: string;
  force: boolean;
  rest: string[];
  keyEnv?: string;
  tool?: string;
  toolArgs?: string;
  keyId?: string;
  generate: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { command: '', config: './mcpgateway.yaml', network: false, http: false, output: './mcpgateway.yaml', force: false, rest: [], generate: false };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '-c' || a === '--config') args.config = argv[++i] as string;
    else if (a === '--network') args.network = true;
    else if (a === '--http') args.http = true;
    else if (a === '-o' || a === '--output') args.output = argv[++i] as string;
    else if (a === '-f' || a === '--force') args.force = true;
    else if (a === '--key-env') args.keyEnv = argv[++i] as string;
    else if (a === '--tool') args.tool = argv[++i] as string;
    else if (a === '--args') args.toolArgs = argv[++i] as string;
    else if (a === '--key') args.keyId = argv[++i] as string;
    else if (a === '--generate') args.generate = true;
    else if (a === '--version' || a === '-V') return { ...args, command: 'version' };
    else if (a === '--help' || a === '-h') return { ...args, command: 'help' };
    else if (!a.startsWith('-')) rest.push(a);
    else throw new Error(`unknown flag "${a}" (see --help)`);
  }
  if (rest.length > 0) args.command = rest[0] as string;
  args.rest = rest.slice(1);
  return args;
}

// Exported for tests.
export { parseArgs };
export type { Args };

/** Apply serve-time CLI overrides to a loaded config. */
export function applyServeFlags(cfg: { upstream: { http: { enabled: boolean } } }, args: Args): void {
  if (args.http) cfg.upstream.http.enabled = true;
}

export async function main(argv: string[]): Promise<void> {
  let args: Args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    console.error(`error: ${(e as Error).message}`);
    process.exitCode = 2;
    return;
  }

  switch (args.command) {
    case 'version':
      console.log(VERSION);
      return;
    case 'help':
    case '':
      console.log(HELP);
      if (args.command === '') process.exitCode = 2;
      return;
    case 'serve':
      await cmdServe(args);
      return;
    case 'validate':
      await cmdValidate(args);
      return;
    case 'namespace':
      await cmdNamespace(args);
      return;
    case 'init':
      cmdInit(args);
      return;
    case 'audit-verify':
      cmdAuditVerify(args);
      return;
    case 'policy-test':
      cmdPolicyTest(args);
      return;
    case 'hash-key':
      await cmdHashKey(args);
      return;
    default:
      console.error(`unknown command "${args.command}" (see --help)`);
      process.exitCode = 2;
  }
}

async function cmdServe(args: Args): Promise<void> {
  const cfg = loadConfigOrExit(args.config, false);
  applyServeFlags(cfg, args);
  if (cfg.auth.disabled) {
    console.error('[mcpgateway] WARNING: auth.disabled=true — HTTP upstream and admin accept unauthenticated requests');
  }
  if (cfg.admin.enabled && cfg.auth.disabled && cfg.admin.host !== '127.0.0.1' && cfg.admin.host !== 'localhost' && cfg.admin.host !== '::1') {
    console.error('[mcpgateway] WARNING: admin API is bound beyond loopback with auth.disabled=true — anyone who can reach it can accept pins and reload. Configure auth.keys.');
  }
  if (cfg.admin.enabled && cfg.admin.allowPublicAdmin) {
    console.error('[mcpgateway] WARNING: admin.allowPublicAdmin=true — admin API is reachable beyond localhost');
  }
  if (cfg.upstream.http.enabled && cfg.upstream.stdio.enabled) {
    console.error(`[mcpgateway] upstream: stdio + Streamable HTTP on ${cfg.upstream.http.host}:${cfg.upstream.http.port}/mcp`);
  }

  const gateway = await startGateway(cfg, { log: (m) => console.error(m) });

  if (cfg.upstream.stdio.enabled) {
    await gateway.upstream.connectStdio();
    console.error(`[mcpgateway] serving ${gateway.getNamespace()?.tools.length ?? 0} unified tools on stdio`);
  }

  const shutdown = () => {
    console.error('[mcpgateway] shutting down…');
    void gateway.close().then(() => process.exit(0));
    // Hard stop if graceful close hangs (a wedged child must not pin us).
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  // Keep the event loop alive for stdio mode (the transport holds it anyway;
  // this is belt-and-braces for http-only mode without admin).
  await new Promise(() => undefined);
}

async function cmdValidate(args: Args): Promise<void> {
  let cfg;
  try {
    cfg = loadConfigFile(args.config, { noNetwork: !args.network });
  } catch (e) {
    reportConfigError(e);
    return;
  }
  for (const w of configWarnings(cfg)) console.log(`warning: ${w}`);
  console.log(`ok: ${cfg.servers.length} server(s), namespace strategy "${cfg.namespace.strategy}", ` +
    `upstream=${[cfg.upstream.stdio.enabled && 'stdio', cfg.upstream.http.enabled && 'http'].filter(Boolean).join('+')}, ` +
    `admin=${cfg.admin.enabled ? `${cfg.admin.host}:${cfg.admin.port}` : 'off'}`);
  console.log('hint: run `mcpgateway namespace` to preview the unified tool table (connects to servers)');
}

async function cmdNamespace(args: Args): Promise<void> {
  // namespace always connects: the table IS the live catalogs.
  const cfg = loadConfigOrExit(args.config, false);
  const servers: DownstreamServer[] = [];
  try {
    for (const sc of cfg.servers) {
      const s = new DownstreamServer(sc, { onCatalogChanged: () => undefined });
      await s.connect();
      servers.push(s);
    }
    const catalogs = servers.map((s) => ({ server: s.name, tools: s.getCatalogs().tools }));
    const ns = buildNamespace(catalogs, cfg.namespace);
    const rows: string[] = [];
    const nameW = Math.max(4, ...ns.tools.map((t) => t.publicName.length));
    rows.push(`${'TOOL'.padEnd(nameW)}  SERVER -> ORIGINAL`);
    for (const t of ns.tools) rows.push(`${t.publicName.padEnd(nameW)}  ${t.server} -> ${t.originalName}`);
    console.log(rows.join('\n'));
    if (ns.collisions.length > 0) {
      console.log(`\n${ns.collisions.length} collision(s) resolved with strategy "${cfg.namespace.strategy}":`);
      for (const c of ns.collisions) {
        console.log(`  "${c.originalName}" (${c.servers.join(', ')})`);
        c.resolvedAs.forEach((r, i) => console.log(`    -> ${r}${c.shadowed.includes(c.servers[i] as string) ? '  [shadowed]' : ''}`));
      }
    }
    for (const w of ns.warnings) console.log(`warning: ${w}`);
  } finally {
    await Promise.all(servers.map((s) => s.close().catch(() => undefined)));
  }
}

function cmdAuditVerify(args: Args): void {
  const base = args.rest[0];
  if (base === undefined) {
    console.error('error: usage: mcpgateway audit-verify <audit.jsonl> [--key-env VAR]');
    process.exitCode = 2;
    return;
  }
  let key: string | undefined;
  if (args.keyEnv !== undefined) {
    key = process.env[args.keyEnv];
    if (key === undefined || key === '') {
      console.error(`error: environment variable ${args.keyEnv} is not set`);
      process.exitCode = 2;
      return;
    }
  }
  // oldest first: base.N ... base.1, base
  const files: string[] = [];
  for (let i = 100; i >= 1; i--) if (existsSync(`${base}.${i}`)) files.push(`${base}.${i}`);
  if (existsSync(base) || files.length === 0) files.push(base); // the live file is absent right after a rotation
  const r = verifyChain(files, key);
  if (!r.ok) {
    console.error(`FAIL: ${r.failure?.file}:${r.failure?.line}: ${r.failure?.reason} (${r.records} record(s) verified before the break)`);
    process.exitCode = 1;
    return;
  }
  console.log(`ok: ${r.records} record(s) in ${files.length} file(s); chain starts from ${r.anchor ?? 'n/a'}`);
  if (r.head) console.log(`head: seq=${r.head.seq} hash=${r.head.hash}  (compare with GET /v1/audit/head stored elsewhere to detect truncation)`);
}

function cmdPolicyTest(args: Args): void {
  if (args.tool === undefined) {
    console.error('error: usage: mcpgateway policy-test --tool NAME [--args \'{"path":"/etc/passwd"}\'] [--key ID] [-c config.yaml]');
    process.exitCode = 2;
    return;
  }
  let callArgs: unknown = {};
  if (args.toolArgs !== undefined) {
    try {
      callArgs = JSON.parse(args.toolArgs);
    } catch {
      console.error('error: --args must be valid JSON');
      process.exitCode = 2;
      return;
    }
  }
  const cfg = loadConfigOrExit(args.config, true);
  const tool = args.tool;
  const notes: string[] = [];
  if (isHidden(cfg.policy, tool)) {
    console.log(`DENY  "${tool}" is hidden by policy.hideTools (callers see "unknown tool")`);
    process.exitCode = 1;
    return;
  }
  if (args.keyId !== undefined) {
    const k = cfg.auth.keys.find((x) => x.id === args.keyId);
    if (k === undefined) {
      console.error(`error: no key with id "${args.keyId}" in the config`);
      process.exitCode = 2;
      return;
    }
    if (k.denyTools?.some((g) => globMatch(g, tool)) || (k.allowTools !== undefined && !k.allowTools.some((g) => globMatch(g, tool)))) {
      console.log(`DENY  key "${k.id}" may not use "${tool}" (allowTools/denyTools; callers see "unknown tool")`);
      process.exitCode = 1;
      return;
    }
    if (k.readOnly) notes.push('key is readOnly: also needs readOnlyHint:true from the server (needs the live catalog, check with `namespace`)');
    if (k.allowServers) notes.push(`key is limited to servers ${k.allowServers.join(', ')} (needs the live catalog, check with \`namespace\`)`);
    if (!k.scopes.includes('tools:call')) notes.push('key has no tools:call scope: HTTP calls are refused before policy runs');
  }
  const v = checkToolCall(cfg.policy, tool, callArgs);
  const observe = cfg.policy.mode === 'observe';
  if (v.decision === 'deny') {
    console.log(`${observe ? 'WOULD DENY (observe mode, call is forwarded)' : 'DENY'}  ${v.reason}: ${v.detail}`);
    for (const n of notes) console.log(`note: ${n}`);
    process.exitCode = observe ? 0 : 1;
    return;
  }
  console.log(`ALLOW  fleet policy lets "${tool}" through`);
  for (const n of notes) console.log(`note: ${n}`);
}

async function cmdHashKey(args: Args): Promise<void> {
  let key: string | undefined;
  let generated = false;
  if (args.generate) {
    key = randomBytes(32).toString('hex');
    generated = true;
  } else if (args.keyEnv !== undefined) {
    key = process.env[args.keyEnv];
  } else if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    key = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
  }
  if (key === undefined || key.length < 16) {
    console.error('error: give a key of at least 16 characters on stdin, via --key-env VAR, or use --generate');
    process.exitCode = 2;
    return;
  }
  if (generated) console.log(`key (give this to the client, it is not stored anywhere): ${key}`);
  console.log(`keyHash: ${hashKey(key)}`);
}

function cmdInit(args: Args): void {
  if (existsSync(args.output) && !args.force) {
    console.error(`error: ${args.output} already exists (use --force to overwrite)`);
    process.exitCode = 2;
    return;
  }
  // Single source of truth: the example file shipped at the package root.
  const examplePath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'mcpgateway.example.yaml');
  let example: string;
  try {
    example = readFileSync(examplePath, 'utf8');
  } catch {
    console.error(`error: cannot read shipped example at ${examplePath}`);
    process.exitCode = 1;
    return;
  }
  writeFileSync(args.output, example, 'utf8');
  console.log(`wrote ${args.output} — edit it, then run: mcpgateway validate -c ${args.output}`);
}

function loadConfigOrExit(path: string, noNetwork: boolean) {
  try {
    return loadConfigFile(path, { noNetwork });
  } catch (e) {
    reportConfigError(e);
    process.exit(1);
    throw new Error('unreachable');
  }
}

function reportConfigError(e: unknown): void {
  if (e instanceof ConfigError) {
    console.error(e.message);
    for (const w of (e as { __warnings?: string[] }).__warnings ?? []) console.error(w);
  } else {
    console.error(`error: ${(e as Error).message}`);
  }
  process.exitCode = 2;
}

