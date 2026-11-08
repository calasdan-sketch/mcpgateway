/**
 * CLI: serve | validate | namespace | init | pin | import
 *
 * In stdio upstream mode, stdout is the MCP channel — ALL operational logging
 * goes to stderr.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { stringify as stringifyYaml } from 'yaml';
import { ConfigError, DEFAULT_REDACT_KEYS, configWarnings, loadConfigFile } from './config.js';
import { startGateway } from './gateway.js';
import { buildNamespace } from './namespace.js';
import { DownstreamServer } from './downstream.js';
import { pinsFileContent } from './pinning.js';
import { VERSION } from './version.js';

const HELP = `mcpgateway ${VERSION} — one process fronting all your MCP servers.

Usage:
  mcpgateway serve [-c config.yaml]     Serve the unified gateway (stdio upstream by default)
  mcpgateway serve --http [-c config]  Also serve Streamable HTTP upstream (uses upstream.http.* settings)
  mcpgateway validate [-c config.yaml]  Validate config (add --network for reachability checks)
  mcpgateway namespace [-c config.yaml] Connect and print the unified tool table
  mcpgateway init [-o out.yaml]         Write a commented starter config
  mcpgateway pin [-c config] [-o pins.json]  Connect and write tool-definition pins (stdout without -o)
  mcpgateway import <.mcp.json>        Print a servers: block converted from a Claude-style .mcp.json
  mcpgateway --version | --help

Options:
  -c, --config <path>   Config file (default: ./mcpgateway.yaml)
  --http                serve: enable the Streamable HTTP upstream too
  --network             validate/namespace: check server reachability (validate skips by default)
  -o, --output <path>   init: output path (default: ./mcpgateway.yaml); pin: pins file (default: stdout)
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
  /** first positional after the command (import: path) */
  target: string;
}

function parseArgs(argv: string[]): Args {
  const args: Args = { command: '', config: './mcpgateway.yaml', network: false, http: false, output: '', force: false, target: '' };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i] as string;
    if (a === '-c' || a === '--config') args.config = argv[++i] as string;
    else if (a === '--network') args.network = true;
    else if (a === '--http') args.http = true;
    else if (a === '-o' || a === '--output') args.output = argv[++i] as string;
    else if (a === '-f' || a === '--force') args.force = true;
    else if (a === '--version' || a === '-V') return { ...args, command: 'version' };
    else if (a === '--help' || a === '-h') return { ...args, command: 'help' };
    else if (!a.startsWith('-')) rest.push(a);
    else throw new Error(`unknown flag "${a}" (see --help)`);
  }
  if (rest.length > 0) args.command = rest[0] as string;
  if (rest.length > 1) args.target = rest[1] as string;
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
    case 'import':
      cmdImport(args);
      return;
    case 'pin':
      await cmdPin(args);
      return;
    case 'init':
      cmdInit(args);
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

function cmdInit(args: Args): void {
  const output = args.output || './mcpgateway.yaml';
  if (existsSync(output) && !args.force) {
    console.error(`error: ${output} already exists (use --force to overwrite)`);
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
  writeFileSync(output, example, 'utf8');
  console.log(`wrote ${output} — edit it, then run: mcpgateway validate -c ${output}`);
  // Printed, never written: the config file may get committed.
  console.log(`generated a gateway key (not saved to the file) — set it in your environment:\n  export GATEWAY_KEY=${randomBytes(32).toString('hex')}`);
}

async function cmdPin(args: Args): Promise<void> {
  const cfg = loadConfigOrExit(args.config, false);
  const servers: DownstreamServer[] = [];
  try {
    for (const sc of cfg.servers) {
      const s = new DownstreamServer(sc, { onCatalogChanged: () => undefined });
      await s.connect();
      servers.push(s);
    }
    const text = pinsFileContent(servers.map((s) => ({ server: s.name, tools: s.getCatalogs().tools })));
    if (args.output) {
      writeFileSync(args.output, text, 'utf8');
      console.error(`wrote ${args.output} — review the diff, then set pinning.file to it`);
    } else {
      process.stdout.write(text);
    }
  } finally {
    await Promise.all(servers.map((s) => s.close().catch(() => undefined)));
  }
}

/**
 * Convert a Claude-style .mcp.json object to gateway `servers:` entries.
 * Literal values under secret-looking env/header names become ${NAME}
 * references, so secrets never land in the generated YAML.
 */
export function mcpJsonToServers(data: unknown): { servers: Array<Record<string, unknown>>; notes: string[] } {
  const obj = (data ?? {}) as Record<string, unknown>;
  const src = (obj['mcpServers'] ?? obj['servers'] ?? obj) as Record<string, unknown>;
  const servers: Array<Record<string, unknown>> = [];
  const notes: string[] = [];
  const used = new Set<string>();
  const secretKey = (k: string) => DEFAULT_REDACT_KEYS.some((r) => k.toLowerCase().includes(r));
  const scrub = (map: unknown, server: string): Record<string, string> | undefined => {
    if (map === null || typeof map !== 'object') return undefined;
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(map as Record<string, unknown>)) {
      const value = String(v);
      if (secretKey(k) && !/^[$][{][A-Za-z_][A-Za-z0-9_]*(:-.*)?[}]$/.test(value)) {
        const envName = k.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
        out[k] = '${' + envName + '}';
        notes.push(`server "${server}": ${k} replaced with \${${envName}} — export ${envName} before serve`);
      } else {
        out[k] = value;
      }
    }
    return out;
  };
  for (const [rawName, entry] of Object.entries(src)) {
    if (entry === null || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    const base = rawName.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^[^a-z0-9]+/, '').slice(0, 29) || 'server';
    let name = base;
    for (let n = 2; used.has(name); n++) name = `${base}-${n}`;
    used.add(name);
    if (typeof e['command'] === 'string') {
      const s: Record<string, unknown> = { name, transport: 'stdio', command: e['command'] };
      if (Array.isArray(e['args'])) s['args'] = e['args'].map(String);
      const env = scrub(e['env'], name);
      if (env !== undefined) s['env'] = env;
      servers.push(s);
    } else if (typeof e['url'] === 'string') {
      if (e['type'] === 'sse') notes.push(`server "${name}": legacy SSE transport — the gateway speaks Streamable HTTP only; check the server supports it`);
      const s: Record<string, unknown> = { name, transport: 'http', url: e['url'] };
      const headers = scrub(e['headers'], name);
      if (headers !== undefined) s['headers'] = headers;
      servers.push(s);
    } else {
      notes.push(`server "${rawName}": no command or url — skipped`);
    }
  }
  return { servers, notes };
}

function cmdImport(args: Args): void {
  let data: unknown;
  try {
    data = JSON.parse(readFileSync(args.target, 'utf8'));
  } catch (e) {
    console.error(args.target === '' ? 'error: usage: mcpgateway import <path-to-.mcp.json>'
      : `error: ${args.target} is unreadable or not valid JSON: ${(e as Error).message}`);
    process.exitCode = 2;
    return;
  }
  const { servers, notes } = mcpJsonToServers(data);
  for (const n of notes) console.error(`note: ${n}`);
  process.stdout.write(stringifyYaml({ servers }));
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

