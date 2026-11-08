/**
 * Config loading, `${VAR}` interpolation, and strict validation.
 *
 * The config file is TRUSTED operator input (like sshd_config): it names the
 * commands to spawn and the URLs to call. Docs say this loudly; `validate`
 * still sanity-checks commands exist and warns on cleartext remote URLs.
 */
import { accessSync, constants, existsSync, readFileSync } from 'node:fs';
import { delimiter as pathDelimiter, join as joinPath } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { globMatch } from './util.js';

export class ConfigError extends Error {
  readonly problems: string[];
  constructor(problems: string[]) {
    super(`invalid config:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.problems = problems;
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ServerConfig {
  name: string;
  transport: 'stdio' | 'http';
  // stdio
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  // http
  url?: string;
  headers?: Record<string, string>;
  // reliability
  timeoutMs: number;
  concurrency: number;
  failureThreshold: number;
  breakerCooldownMs: number;
  healthCheckMs: number;
}

export type NamespaceStrategy = 'prefix' | 'priority' | 'explicit';

export interface NamespaceConfig {
  strategy: NamespaceStrategy;
  separator: string;
  priority: string[];
  mappings: Record<string, string>;
  aliases: Record<string, string>; // "<server>:<tool>" -> custom public name
}

export interface RateLimitRule {
  rps: number;
  burst: number;
}

export interface ArgRule {
  allow?: string[];
  deny?: string[];
}

export interface PolicyConfig {
  mode: 'enforce' | 'observe';
  allowTools: string[];
  denyTools: string[];
  hideTools: string[];
  argRules: Record<string, ArgRule>;
  responseRedact: string[];
  responseBlock: string[];
  responseWarn: string[];
  scanWindowChars: number;
  /** How argRules substrings are compared (defaults: exact, case-sensitive; both off) */
  argMatch?: { ignoreCase: boolean; normalizePaths: boolean };
  /** Rug-pull defense: pin each tool's description+schema hash (trust on first use). */
  pinning?: PinningConfig;
}

export interface PinningConfig {
  /** off: nothing; warn: log+metric on change; block: quarantine changed tools until accepted */
  mode: 'off' | 'warn' | 'block';
  /** JSON file the pins persist in (omit = in-memory, lost on restart) */
  file?: string;
}

export interface AuthKey {
  id: string;
  /** plaintext key (empty when keyHash is used) */
  key: string;
  /** "sha256:<64 hex>" digest of the key — the config then never holds the secret (see `mcpgateway hash-key`) */
  keyHash?: string;
  /** key stops working at this instant (ISO 8601); checked on every request */
  expiresAt?: number;
  /** only tools whose server-declared annotations say readOnlyHint: true are visible/callable; no hint = not read-only */
  readOnly?: boolean;
  /** restrict tools, resources and prompts to these servers (globs over server names) */
  allowServers?: string[];
  scopes: string[];
  /** per-key tool visibility (globs over public names); deny wins. Omitted = everything policy allows. */
  allowTools?: string[];
  denyTools?: string[];
  /** per-key budget across ALL tools, so one noisy agent cannot starve the others */
  rateLimit?: RateLimitRule;
}

export interface ExposureConfig {
  /** full: every tool in tools/list (default). search: two meta-tools + alwaysExpose. */
  mode: 'full' | 'search';
  /** globs of public tool names that stay listed directly in search mode */
  alwaysExpose: string[];
}

export interface AuditConfig {
  path: string;
  logArgs: boolean;
  redactKeys: string[];
  maxArgsChars: number;
  maxSizeMB: number;
  keepFiles: number;
  /** tamper-evident hash chain over records (see `mcpgateway audit-verify`) */
  chain?: boolean;
  /** redact well-known credential shapes (bearer tokens, JWTs, sk-/ghp_/AKIA/xox keys, PEM headers, URL passwords) inside any string value. Default true. */
  redactValues?: boolean;
  /** optional HMAC secret for the chain; without it an attacker who can rewrite the file can recompute hashes */
  chainKey?: string;
}

export interface AdminConfig {
  enabled: boolean;
  host: string;
  port: number;
  allowPublicAdmin: boolean;
  /** accepted Host header names (DNS-rebinding defense). Loopback binds default to loopback names only. */
  allowedHosts: string[];
}

export interface UpstreamConfig {
  stdio: { enabled: boolean };
  http: { enabled: boolean; host: string; port: number; maxSessions: number; allowedHosts: string[]; allowedOrigins: string[] };
}

export interface GatewayConfig {
  name: string;
  servers: ServerConfig[];
  namespace: NamespaceConfig;
  defaultRateLimit: RateLimitRule;
  perToolRateLimits: Record<string, RateLimitRule>;
  policy: PolicyConfig;
  auth: { disabled: boolean; keys: AuthKey[] };
  audit: AuditConfig;
  admin: AdminConfig;
  upstream: UpstreamConfig;
  exposure: ExposureConfig;
  globalMaxInflight: number;
  maxResultChars: number;
}

export const VALID_SCOPES = ['tools:call', 'tools:list', 'resources:*', 'prompts:*', 'admin'] as const;

const SERVER_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const TOOL_NAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;

// ---------------------------------------------------------------------------
// Env interpolation
// ---------------------------------------------------------------------------

const ENV_REF = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}/g;

/** Expand ${VAR} and ${VAR:-default}; throws naming the variable when unset. */
export function interpolateEnv(value: string, context: string): string {
  return value.replace(ENV_REF, (_m, name: string, def: string | undefined) => {
    const v = process.env[name];
    if (v !== undefined) return v;
    if (def !== undefined) return def;
    throw new ConfigError([`${context}: environment variable ${name} is not set and has no default (use \${${name}:-default})`]);
  });
}

function interpolateDeep(value: unknown, context: string): unknown {
  if (typeof value === 'string') return interpolateEnv(value, context);
  if (Array.isArray(value)) return value.map((v, i) => interpolateDeep(v, `${context}[${i}]`));
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = interpolateDeep(v, `${context}.${k}`);
    return out;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

export type Raw = Record<string, unknown>;

function isRaw(v: unknown): v is Raw {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function str(v: unknown): v is string {
  return typeof v === 'string';
}

function num(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function problems(): string[] {
  return [];
}

function reqStr(raw: Raw, key: string, ctx: string, problems: string[]): string | undefined {
  const v = raw[key];
  if (!str(v) || v.length === 0) {
    problems.push(`${ctx}: "${key}" must be a non-empty string`);
    return undefined;
  }
  return v;
}

function optNum(raw: Raw, key: string, ctx: string, def: number, min: number, problems: string[]): number {
  const v = raw[key];
  if (v === undefined) return def;
  if (!num(v) || v < min) {
    problems.push(`${ctx}: "${key}" must be a number >= ${min}`);
    return def;
  }
  return v;
}

function strArray(raw: Raw, key: string, ctx: string, problems: string[]): string[] {
  const v = raw[key];
  if (v === undefined) return [];
  if (!Array.isArray(v) || !v.every(str)) {
    problems.push(`${ctx}: "${key}" must be an array of strings`);
    return [];
  }
  return v as string[];
}

function strMap(raw: Raw, key: string, ctx: string, problems: string[]): Record<string, string> {
  const v = raw[key];
  if (v === undefined) return {};
  if (!isRaw(v) || !Object.values(v).every(str)) {
    problems.push(`${ctx}: "${key}" must be a map of string -> string`);
    return {};
  }
  return v as Record<string, string>;
}

/** Unknown keys in a section: error for security-bearing sections (a typo must not silently disable a rule), warning elsewhere. */
function checkKnown(raw: Raw, known: string[], where: string, fatal: boolean, p: string[]): void {
  const bad = Object.keys(raw).filter((k) => !known.includes(k));
  if (bad.length === 0) return;
  const hint = bad.map((k) => {
    const near = known.find((n) => n.toLowerCase() === k.toLowerCase() || n.toLowerCase() === k.toLowerCase() + 's' || n.toLowerCase() + 's' === k.toLowerCase());
    return near ? `"${k}" (did you mean "${near}"?)` : `"${k}"`;
  });
  p.push(fatal ? `${where}: unknown key(s) ${hint.join(', ')}` : `${where}: WARNING: unknown key(s) ignored: ${hint.join(', ')}`);
}

function rateLimit(raw: unknown, ctx: string, problems: string[]): RateLimitRule | undefined {
  if (!isRaw(raw)) {
    problems.push(`${ctx}: rate limit must be {rps, burst}`);
    return undefined;
  }
  const rps = raw['rps'];
  const burst = raw['burst'];
  if (!num(rps) || rps <= 0 || !num(burst) || burst < 1) {
    problems.push(`${ctx}: rate limit needs positive "rps" and "burst" >= 1`);
    return undefined;
  }
  return { rps, burst };
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

export interface LoadOptions {
  /** Skip reachability/command-exists checks (offline validation). */
  noNetwork?: boolean;
}

export function loadConfigFile(path: string, opts: LoadOptions = {}): GatewayConfig {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (e) {
    throw new ConfigError([`cannot read config file ${path}: ${(e as Error).message}`]);
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (e) {
    throw new ConfigError([`YAML parse error in ${path}: ${(e as Error).message}`]);
  }
  if (!isRaw(parsed)) throw new ConfigError([`${path}: top level must be a mapping`]);
  const interpolated = interpolateDeep(parsed, 'config') as Raw;
  return validateConfig(interpolated, path, opts);
}

export function validateConfig(raw: Raw, source: string, opts: LoadOptions = {}): GatewayConfig {
  const p = problems();
  const ctx = (s: string) => `${source}: ${s}`;

  // ---- gateway name ----
  const gwRaw = raw['gateway'];
  const name = (isRaw(gwRaw) && str(gwRaw['name']) ? (gwRaw['name'] as string) : 'mcpgateway');

  // ---- servers ----
  const serversRaw = raw['servers'];
  const servers: ServerConfig[] = [];
  const seenNames = new Set<string>();
  if (!Array.isArray(serversRaw) || serversRaw.length === 0) {
    p.push(ctx('"servers" must be a non-empty array'));
  } else {
    serversRaw.forEach((s, i) => {
      const sc = `${ctx(`servers[${i}]`)}`;
      if (!isRaw(s)) {
        p.push(`${sc}: must be a mapping`);
        return;
      }
      const nm = reqStr(s, 'name', sc, p);
      if (nm !== undefined) {
        if (!SERVER_NAME_RE.test(nm)) p.push(`${sc}: "name" must match ${SERVER_NAME_RE} (lowercase, used in tool prefixes)`);
        if (seenNames.has(nm)) p.push(`${sc}: duplicate server name "${nm}"`);
        seenNames.add(nm);
      }
      const transport = s['transport'];
      if (transport !== 'stdio' && transport !== 'http') {
        p.push(`${sc}: "transport" must be "stdio" or "http"`);
        return;
      }
      const cfg: ServerConfig = {
        name: nm ?? `server-${i}`,
        transport,
        timeoutMs: optNum(s, 'timeoutMs', sc, 60_000, 1_000, p),
        concurrency: optNum(s, 'concurrency', sc, transport === 'stdio' ? 1 : 8, 1, p),
        failureThreshold: optNum(s, 'failureThreshold', sc, 5, 1, p),
        breakerCooldownMs: optNum(s, 'breakerCooldownMs', sc, 30_000, 1_000, p),
        healthCheckMs: optNum(s, 'healthCheckMs', sc, 30_000, 5_000, p),
      };
      if (transport === 'stdio') {
        const command = reqStr(s, 'command', sc, p);
        if (command) {
          cfg.command = command;
          if (!opts.noNetwork) {
            // command may be a bare binary resolved via PATH; check resolvability
            const resolved = hasPathSeparator(command) ? commandCandidates(command).some((c) => existsSync(c)) : commandResolvable(command);
            if (!resolved) p.push(`${sc}: command "${command}" not found (not on PATH and not an existing path)`);
          }
        }
        const args = s['args'];
        if (args !== undefined) {
          if (!Array.isArray(args) || !args.every(str)) p.push(`${sc}: "args" must be an array of strings (no shell: argv only)`);
          else cfg.args = args as string[];
        }
        cfg.env = strMap(s, 'env', sc, p);
        const cwd = s['cwd'];
        if (cwd !== undefined) {
          if (!str(cwd)) p.push(`${sc}: "cwd" must be a string`);
          else cfg.cwd = cwd;
        }
      } else {
        const url = reqStr(s, 'url', sc, p);
        if (url) {
          let u: URL;
          try {
            u = new URL(url);
          } catch {
            p.push(`${sc}: "url" is not a valid URL`);
            u = undefined as unknown as URL;
          }
          if (u && u.protocol !== 'http:' && u.protocol !== 'https:') {
            p.push(`${sc}: "url" must be http(s)`);
          } else if (u && u.protocol === 'http:' && !isLocalhost(u.hostname)) {
            p.push(`${sc}: WARNING — cleartext http to non-localhost host "${u.hostname}" (credentials in headers would travel unencrypted)`);
          }
          cfg.url = url;
        }
        cfg.headers = strMap(s, 'headers', sc, p);
      }
      servers.push(cfg);
    });
  }

  // ---- namespace ----
  const nsRaw = isRaw(raw['namespace']) ? (raw['namespace'] as Raw) : {};
  const strategy = nsRaw['strategy'];
  const namespace: NamespaceConfig = {
    strategy: strategy === undefined ? 'prefix' : (strategy as NamespaceStrategy),
    separator: '__',
    priority: [],
    mappings: {},
    aliases: {},
  };
  if (!['prefix', 'priority', 'explicit'].includes(namespace.strategy)) {
    p.push(ctx(`namespace.strategy must be prefix|priority|explicit, got "${String(strategy)}"`));
    namespace.strategy = 'prefix';
  }
  const sep = nsRaw['separator'];
  if (sep !== undefined) {
    if (!str(sep) || !/^[A-Za-z0-9_]{1,4}$/.test(sep)) p.push(ctx('namespace.separator must be 1-4 chars of [A-Za-z0-9_]'));
    else namespace.separator = sep;
  }
  namespace.priority = strArray(nsRaw, 'priority', ctx('namespace'), p);
  const mappingsRaw = nsRaw['mappings'];
  if (mappingsRaw !== undefined) {
    if (!isRaw(mappingsRaw) || !Object.values(mappingsRaw).every(str)) {
      p.push(ctx('namespace.mappings must be {toolName: serverName}'));
    } else {
      namespace.mappings = mappingsRaw as Record<string, string>;
      for (const [tool, srv] of Object.entries(namespace.mappings)) {
        if (!seenNames.has(srv)) p.push(ctx(`namespace.mappings["${tool}"] references unknown server "${srv}"`));
      }
    }
  }
  const aliasesRaw = nsRaw['aliases'];
  if (aliasesRaw !== undefined) {
    if (!isRaw(aliasesRaw) || !Object.values(aliasesRaw).every(str)) {
      p.push(ctx('namespace.aliases must be {"<server>:<tool>": "<publicName>"}'));
    } else {
      for (const [from, to] of Object.entries(aliasesRaw as Record<string, string>)) {
        if (!/^[^:]+:[^:]+$/.test(from)) p.push(ctx(`namespace.aliases key "${from}" must look like "<server>:<tool>"`));
        if (!TOOL_NAME_RE.test(to)) p.push(ctx(`namespace.aliases["${from}"] = "${to}" is not a legal MCP tool name`));
        const [srv] = from.split(':');
        if (srv && !seenNames.has(srv)) p.push(ctx(`namespace.aliases["${from}"] references unknown server "${srv}"`));
      }
      namespace.aliases = aliasesRaw as Record<string, string>;
    }
  }
  if (namespace.strategy === 'priority') {
    for (const s of namespace.priority) {
      if (!seenNames.has(s)) p.push(ctx(`namespace.priority references unknown server "${s}"`));
    }
  }

  // ---- rate limits ----
  const rlRaw = isRaw(raw['rateLimits']) ? (raw['rateLimits'] as Raw) : {};
  const defRaw = rlRaw['default'];
  const defaultRateLimit = defRaw === undefined ? { rps: 10, burst: 20 } : rateLimit(defRaw, ctx('rateLimits.default'), p);
  const perToolRateLimits: Record<string, RateLimitRule> = {};
  const toolsRaw = rlRaw['tools'];
  if (toolsRaw !== undefined) {
    if (!isRaw(toolsRaw)) p.push(ctx('rateLimits.tools must be a mapping'));
    else {
      for (const [tool, rule] of Object.entries(toolsRaw)) {
        const r = rateLimit(rule, ctx(`rateLimits.tools["${tool}"]`), p);
        if (r) perToolRateLimits[tool] = r;
      }
    }
  }

  // ---- policy ----
  const polRaw = isRaw(raw['policy']) ? (raw['policy'] as Raw) : {};
  const mode = polRaw['mode'];
  const policy: PolicyConfig = {
    mode: mode === undefined ? 'enforce' : (mode as 'enforce' | 'observe'),
    allowTools: strArray(polRaw, 'allowTools', ctx('policy'), p),
    denyTools: strArray(polRaw, 'denyTools', ctx('policy'), p),
    hideTools: strArray(polRaw, 'hideTools', ctx('policy'), p),
    argRules: {},
    responseRedact: strArray(polRaw, 'responseRedact', ctx('policy'), p),
    responseBlock: strArray(polRaw, 'responseBlock', ctx('policy'), p),
    responseWarn: strArray(polRaw, 'responseWarn', ctx('policy'), p),
    scanWindowChars: optNum(polRaw, 'scanWindowChars', ctx('policy'), 65536, 1024, p),
    pinning: { mode: 'off' } as PinningConfig,
  };
  if (policy.mode !== 'enforce' && policy.mode !== 'observe') {
    p.push(ctx('policy.mode must be enforce|observe'));
    policy.mode = 'enforce';
  }
  checkKnown(polRaw, ['mode', 'allowTools', 'denyTools', 'hideTools', 'argRules', 'responseRedact', 'responseBlock', 'responseWarn', 'scanWindowChars', 'pinning', 'argMatch'], ctx('policy'), true, p);
  const argMatch = { ignoreCase: false, normalizePaths: false };
  policy.argMatch = argMatch;
  const amRaw = polRaw['argMatch'];
  if (amRaw !== undefined) {
    if (!isRaw(amRaw)) p.push(ctx('policy.argMatch must be {ignoreCase?, normalizePaths?}'));
    else {
      checkKnown(amRaw, ['ignoreCase', 'normalizePaths'], ctx('policy.argMatch'), true, p);
      for (const k of ['ignoreCase', 'normalizePaths'] as const) {
        const v = amRaw[k];
        if (v === undefined) continue;
        if (typeof v !== 'boolean') p.push(ctx(`policy.argMatch.${k} must be boolean`));
        else argMatch[k] = v;
      }
    }
  }
  const pinning: PinningConfig = { mode: 'off' };
  policy.pinning = pinning;
  const pinRaw = polRaw['pinning'];
  if (pinRaw !== undefined) {
    if (!isRaw(pinRaw)) p.push(ctx('policy.pinning must be {mode, file?}'));
    else {
      checkKnown(pinRaw, ['mode', 'file'], ctx('policy.pinning'), true, p);
      const m = pinRaw['mode'];
      if (m !== 'off' && m !== 'warn' && m !== 'block') p.push(ctx('policy.pinning.mode must be off|warn|block'));
      else pinning.mode = m;
      if (pinRaw['file'] !== undefined) {
        if (!str(pinRaw['file']) || pinRaw['file'].length === 0) p.push(ctx('policy.pinning.file must be a non-empty string'));
        else pinning.file = pinRaw['file'];
      }
      if (pinning.mode === 'block' && pinning.file === undefined) {
        p.push(ctx('policy.pinning.mode "block" needs policy.pinning.file (in-memory pins would re-trust a malicious change on every restart)'));
      }
    }
  }
  if (policy.allowTools.length === 0) policy.allowTools = ['*'];
  const argRulesRaw = polRaw['argRules'];
  if (argRulesRaw !== undefined) {
    if (!isRaw(argRulesRaw)) p.push(ctx('policy.argRules must be a mapping'));
    else {
      for (const [tool, rule] of Object.entries(argRulesRaw)) {
        if (!isRaw(rule)) {
          p.push(ctx(`policy.argRules["${tool}"] must be {allow?, deny?}`));
          continue;
        }
        const ar: ArgRule = {};
        for (const k of ['allow', 'deny'] as const) {
          const v = rule[k];
          if (v !== undefined) {
            if (!Array.isArray(v) || !v.every(str)) p.push(ctx(`policy.argRules["${tool}"].${k} must be an array of strings (substring matchers)`));
            else ar[k] = v as string[];
          }
        }
        policy.argRules[tool] = ar;
      }
    }
  }
  // validate glob patterns compile (they always do — globMatch is ReDoS-safe —
  // but catch typos like unbalanced intent early is unnecessary; skip)

  // ---- auth ----
  const authRaw = isRaw(raw['auth']) ? (raw['auth'] as Raw) : {};
  checkKnown(authRaw, ['disabled', 'keys'], ctx('auth'), true, p);
  const authDisabled = authRaw['disabled'] === true;
  const keys: AuthKey[] = [];
  const keysRaw = authRaw['keys'];
  if (keysRaw !== undefined) {
    if (!Array.isArray(keysRaw)) p.push(ctx('auth.keys must be an array'));
    else {
      const seenIds = new Set<string>();
      keysRaw.forEach((k, i) => {
        const kc = `${ctx(`auth.keys[${i}]`)}`;
        if (!isRaw(k)) {
          p.push(`${kc}: must be a mapping`);
          return;
        }
        checkKnown(k, ['id', 'key', 'keyHash', 'scopes', 'allowTools', 'denyTools', 'rateLimit', 'expiresAt', 'readOnly', 'allowServers'], kc, true, p);
        const id = reqStr(k, 'id', kc, p);
        let key = '';
        let keyHash: string | undefined;
        if (k['key'] !== undefined && k['keyHash'] !== undefined) p.push(`${kc}: set either "key" or "keyHash", not both`);
        else if (k['keyHash'] !== undefined) {
          if (!str(k['keyHash']) || !/^sha256:[0-9a-f]{64}$/.test(k['keyHash'])) p.push(`${kc}: "keyHash" must look like sha256:<64 lowercase hex> (make one with: mcpgateway hash-key)`);
          else keyHash = k['keyHash'];
        } else key = reqStr(k, 'key', kc, p) ?? '';
        let expiresAt: number | undefined;
        if (k['expiresAt'] !== undefined) {
          const raw = k['expiresAt'];
          const t = raw instanceof Date ? raw.getTime() : str(raw) ? Date.parse(raw) : Number.NaN;
          if (Number.isNaN(t)) p.push(`${kc}: "expiresAt" must be an ISO 8601 date/time (e.g. 2027-01-31T00:00:00Z)`);
          else expiresAt = t;
        }
        if (k['readOnly'] !== undefined && typeof k['readOnly'] !== 'boolean') p.push(`${kc}: "readOnly" must be boolean`);
        const keyServers = k['allowServers'] === undefined ? undefined : strArray(k, 'allowServers', kc, p);
        const keyAllow = k['allowTools'] === undefined ? undefined : strArray(k, 'allowTools', kc, p);
        const keyDeny = k['denyTools'] === undefined ? undefined : strArray(k, 'denyTools', kc, p);
        const keyRate = k['rateLimit'] === undefined ? undefined : rateLimit(k['rateLimit'], `${kc}.rateLimit`, p);
        if (id && seenIds.has(id)) p.push(`${kc}: duplicate key id "${id}"`);
        if (id) seenIds.add(id);
        const scopesRaw = k['scopes'];
        const scopes: string[] = [];
        if (scopesRaw === undefined) scopes.push('tools:call', 'tools:list');
        else if (!Array.isArray(scopesRaw) || !scopesRaw.every(str)) p.push(`${kc}: "scopes" must be an array of strings`);
        else {
          for (const s of scopesRaw as string[]) {
            if (!(VALID_SCOPES as readonly string[]).includes(s)) p.push(`${kc}: unknown scope "${s}" (valid: ${VALID_SCOPES.join(', ')})`);
            else scopes.push(s);
          }
        }
        if (id && (key || keyHash)) {
          if (key && key.length < 16) p.push(`${kc}: key is shorter than 16 chars — use a long random secret`);
          if (/^change-?me/i.test(key)) p.push(`${kc}: key looks like a placeholder ("changeme...") — anyone who has read the docs knows it; use a real secret`);
          const entry: AuthKey = { id, key, scopes };
          if (keyHash !== undefined) entry.keyHash = keyHash;
          if (expiresAt !== undefined) entry.expiresAt = expiresAt;
          if (k['readOnly'] === true) entry.readOnly = true;
          if (keyServers !== undefined) entry.allowServers = keyServers;
          if (keyAllow !== undefined) entry.allowTools = keyAllow;
          if (keyDeny !== undefined) entry.denyTools = keyDeny;
          if (keyRate !== undefined) entry.rateLimit = keyRate;
          keys.push(entry);
        }
      });
    }
  }
  if (!authDisabled && keys.length === 0) {
    p.push(ctx('auth.keys is empty and auth.disabled is not true — HTTP upstream/admin would accept nobody (or set auth.disabled: true explicitly)'));
  }

  // ---- audit ----
  const audRaw = isRaw(raw['audit']) ? (raw['audit'] as Raw) : {};
  const audit: AuditConfig = {
    path: './mcpgateway-audit.jsonl',
    logArgs: true,
    redactKeys: ['token', 'secret', 'password', 'passwd', 'api_key', 'apikey', 'authorization', 'cookie', 'session', 'credential'],
    maxArgsChars: 8192,
    maxSizeMB: 100,
    keepFiles: 5,
    chain: false,
    redactValues: true,
  };
  checkKnown(audRaw, ['path', 'logArgs', 'redactKeys', 'maxArgsChars', 'maxSizeMB', 'keepFiles', 'chain', 'chainKey', 'redactValues'], ctx('audit'), false, p);
  if (audRaw['redactValues'] !== undefined) {
    if (typeof audRaw['redactValues'] !== 'boolean') p.push(ctx('audit.redactValues must be boolean'));
    else audit.redactValues = audRaw['redactValues'];
  }
  if (audRaw['chain'] !== undefined) {
    if (typeof audRaw['chain'] !== 'boolean') p.push(ctx('audit.chain must be boolean'));
    else audit.chain = audRaw['chain'];
  }
  if (audRaw['chainKey'] !== undefined) {
    if (!str(audRaw['chainKey']) || audRaw['chainKey'].length < 16) p.push(ctx('audit.chainKey must be a string of at least 16 chars'));
    else audit.chainKey = audRaw['chainKey'];
  }
  if (audit.chainKey !== undefined && !audit.chain) p.push(ctx('audit.chainKey is set but audit.chain is not true'));
  if (audRaw['path'] !== undefined) {
    if (!str(audRaw['path'])) p.push(ctx('audit.path must be a string'));
    else audit.path = audRaw['path'];
  }
  if (audRaw['logArgs'] !== undefined) {
    if (typeof audRaw['logArgs'] !== 'boolean') p.push(ctx('audit.logArgs must be boolean'));
    else audit.logArgs = audRaw['logArgs'];
  }
  const rk = audRaw['redactKeys'];
  if (rk !== undefined) {
    if (!Array.isArray(rk) || !rk.every(str)) p.push(ctx('audit.redactKeys must be an array of strings'));
    else audit.redactKeys = rk as string[];
  }
  audit.maxArgsChars = optNum(audRaw, 'maxArgsChars', ctx('audit'), 8192, 256, p);
  audit.maxSizeMB = optNum(audRaw, 'maxSizeMB', ctx('audit'), 100, 1, p);
  audit.keepFiles = optNum(audRaw, 'keepFiles', ctx('audit'), 5, 1, p);

  // ---- admin ----
  const admRaw = isRaw(raw['admin']) ? (raw['admin'] as Raw) : {};
  const admin: AdminConfig = {
    enabled: true,
    host: '127.0.0.1',
    port: 3001,
    allowPublicAdmin: false,
    allowedHosts: [],
  };
  if (admRaw['enabled'] !== undefined) {
    if (typeof admRaw['enabled'] !== 'boolean') p.push(ctx('admin.enabled must be boolean'));
    else admin.enabled = admRaw['enabled'];
  }
  if (admRaw['host'] !== undefined) {
    if (!str(admRaw['host'])) p.push(ctx('admin.host must be a string'));
    else admin.host = admRaw['host'];
  }
  admin.port = optNum(admRaw, 'port', ctx('admin'), 3001, 0, p);
  checkKnown(admRaw, ['enabled', 'host', 'port', 'allowPublicAdmin', 'allowedHosts'], ctx('admin'), false, p);
  admin.allowedHosts = strArray(admRaw, 'allowedHosts', ctx('admin'), p);
  if (admRaw['allowPublicAdmin'] !== undefined) {
    if (typeof admRaw['allowPublicAdmin'] !== 'boolean') p.push(ctx('admin.allowPublicAdmin must be boolean'));
    else admin.allowPublicAdmin = admRaw['allowPublicAdmin'];
  }
  if (admin.enabled && isPublicBind(admin.host) && !admin.allowPublicAdmin) {
    p.push(ctx(`admin.host "${admin.host}" is public but admin.allowPublicAdmin is not true — refusing (bind 127.0.0.1 or set the flag explicitly)`));
  }

  // ---- upstream ----
  const upRaw = isRaw(raw['upstream']) ? (raw['upstream'] as Raw) : {};
  const stdioRaw = isRaw(upRaw['stdio']) ? (upRaw['stdio'] as Raw) : {};
  const httpRaw = isRaw(upRaw['http']) ? (upRaw['http'] as Raw) : {};
  const upstream: UpstreamConfig = {
    stdio: { enabled: stdioRaw['enabled'] !== undefined ? stdioRaw['enabled'] === true : true },
    http: { enabled: false, host: '127.0.0.1', port: 3000, maxSessions: 128, allowedHosts: [], allowedOrigins: [] },
  };
  if (typeof stdioRaw['enabled'] !== 'undefined' && typeof stdioRaw['enabled'] !== 'boolean') {
    p.push(ctx('upstream.stdio.enabled must be boolean'));
  }
  if (httpRaw['enabled'] !== undefined) {
    if (typeof httpRaw['enabled'] !== 'boolean') p.push(ctx('upstream.http.enabled must be boolean'));
    else upstream.http.enabled = httpRaw['enabled'];
  }
  if (httpRaw['host'] !== undefined) {
    if (!str(httpRaw['host'])) p.push(ctx('upstream.http.host must be a string'));
    else upstream.http.host = httpRaw['host'];
  }
  upstream.http.port = optNum(httpRaw, 'port', ctx('upstream.http'), 3000, 0, p);
  upstream.http.maxSessions = optNum(httpRaw, 'maxSessions', ctx('upstream.http'), 128, 1, p);
  checkKnown(httpRaw, ['enabled', 'host', 'port', 'maxSessions', 'allowedHosts', 'allowedOrigins'], ctx('upstream.http'), false, p);
  upstream.http.allowedHosts = strArray(httpRaw, 'allowedHosts', ctx('upstream.http'), p).map((h) => h.toLowerCase());
  upstream.http.allowedOrigins = strArray(httpRaw, 'allowedOrigins', ctx('upstream.http'), p).map((o) => o.toLowerCase());
  if (!upstream.stdio.enabled && !upstream.http.enabled) {
    p.push(ctx('at least one upstream transport (stdio or http) must be enabled'));
  }

  // ---- exposure ----
  const expRaw = isRaw(raw['exposure']) ? (raw['exposure'] as Raw) : {};
  checkKnown(expRaw, ['mode', 'alwaysExpose'], ctx('exposure'), true, p);
  const exposure: ExposureConfig = { mode: 'full', alwaysExpose: strArray(expRaw, 'alwaysExpose', ctx('exposure'), p) };
  if (expRaw['mode'] !== undefined) {
    if (expRaw['mode'] !== 'full' && expRaw['mode'] !== 'search') p.push(ctx('exposure.mode must be full|search'));
    else exposure.mode = expRaw['mode'];
  }

  // ---- global limits ----
  const globalMaxInflight = optNum(raw, 'globalMaxInflight', source, 256, 1, p);
  const maxResultChars = optNum(raw, 'maxResultChars', source, 10_000_000, 1024, p);

  // unknown top-level keys: warn via problems? Panel said warn, not fail.
  // We surface them as warnings through the returned config instead.
  const knownTop = new Set(['gateway', 'servers', 'namespace', 'rateLimits', 'policy', 'auth', 'audit', 'admin', 'upstream', 'exposure', 'globalMaxInflight', 'maxResultChars']);
  const unknownTop = Object.keys(raw).filter((k) => !knownTop.has(k));
  if (unknownTop.length > 0) {
    // non-fatal: attach to stderr at serve time via a thrown-adjacent channel.
    // Simplest: push as a special problem the CLI prints as warning.
    p.push(ctx(`WARNING: unknown top-level keys ignored: ${unknownTop.join(', ')}`));
  }

  // fail on real problems; warnings are prefixed and filtered by the caller.
  const real = p.filter((x) => !x.includes('WARNING'));
  const warnings = p.filter((x) => x.includes('WARNING'));
  if (real.length > 0) throw new ConfigError(real);

  const cfg: GatewayConfig = {
    name,
    servers,
    namespace,
    defaultRateLimit: defaultRateLimit ?? { rps: 10, burst: 20 },
    perToolRateLimits,
    policy,
    auth: { disabled: authDisabled, keys },
    audit,
    admin,
    upstream,
    exposure,
    globalMaxInflight,
    maxResultChars,
  };
  (cfg as { __warnings?: string[] }).__warnings = warnings;
  return cfg;
}

/** Warnings collected during validation (unknown keys etc.). Non-fatal. */
export function configWarnings(cfg: GatewayConfig): string[] {
  return (cfg as { __warnings?: string[] }).__warnings ?? [];
}

function isLocalhost(host: string): boolean {
  const h = host.toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h.endsWith('.localhost');
}

function isPublicBind(host: string): boolean {
  return host === '0.0.0.0' || host === '::';
}

/**
 * File names to try for a bare command in one PATH directory. On Windows a
 * command like `npx` is really `npx.cmd`, found through PATHEXT; without this
 * `validate` warned about every npm-installed server on Windows.
 */
export function commandCandidates(command: string, platform: string = process.platform, pathExt: string = process.env['PATHEXT'] ?? '.COM;.EXE;.BAT;.CMD'): string[] {
  if (platform !== 'win32') return [command];
  const exts = pathExt.split(';').filter((e) => e.length > 0);
  const hasExt = exts.some((e) => command.toLowerCase().endsWith(e.toLowerCase()));
  return hasExt ? [command] : [command, ...exts.map((e) => command + e.toLowerCase()), ...exts.map((e) => command + e.toUpperCase())];
}

/** Is this command a path (contains a directory separator) rather than a bare name looked up on PATH? Windows also uses a backslash. */
export function hasPathSeparator(command: string, platform: string = process.platform): boolean {
  return platform === 'win32' ? /[\\/]/.test(command) : command.includes('/');
}

function commandResolvable(command: string): boolean {
  // bare binary: search PATH manually (no shell — never spawn one for this)
  const pathEnv = process.env['PATH'] ?? process.env['Path'] ?? '';
  for (const dir of pathEnv.split(pathDelimiter)) {
    if (!dir) continue;
    for (const name of commandCandidates(command)) {
      try {
        accessSync(joinPath(dir, name), constants.X_OK);
        return true;
      } catch {
        /* next */
      }
    }
  }
  return false;
}

/** Does this public tool name match any allow/deny-style glob list? Exported for policy use. */
export function matchesAny(patterns: string[], value: string): boolean {
  return patterns.some((pat) => globMatch(pat, value));
}

// re-export for namespace/policy convenience
export { globMatch };
