/**
 * Config loading, `${VAR}` interpolation, and strict validation.
 *
 * The config file is TRUSTED operator input (like sshd_config): it names the
 * commands to spawn and the URLs to call. Docs say this loudly; `validate`
 * still sanity-checks commands exist and warns on cleartext remote URLs.
 */
import { accessSync, constants, existsSync, readFileSync } from 'node:fs';
import { delimiter as pathDelimiter } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { globMatch } from './util.js';
export class ConfigError extends Error {
    problems;
    constructor(problems) {
        super(`invalid config:\n  - ${problems.join('\n  - ')}`);
        this.name = 'ConfigError';
        this.problems = problems;
    }
}
export const VALID_SCOPES = ['tools:call', 'tools:list', 'resources:*', 'prompts:*', 'admin'];
const SERVER_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const TOOL_NAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;
// ---------------------------------------------------------------------------
// Env interpolation
// ---------------------------------------------------------------------------
const ENV_REF = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}/g;
/** Expand ${VAR} and ${VAR:-default}; throws naming the variable when unset. */
export function interpolateEnv(value, context) {
    return value.replace(ENV_REF, (_m, name, def) => {
        const v = process.env[name];
        if (v !== undefined)
            return v;
        if (def !== undefined)
            return def;
        throw new ConfigError([`${context}: environment variable ${name} is not set and has no default (use \${${name}:-default})`]);
    });
}
function interpolateDeep(value, context) {
    if (typeof value === 'string')
        return interpolateEnv(value, context);
    if (Array.isArray(value))
        return value.map((v, i) => interpolateDeep(v, `${context}[${i}]`));
    if (value !== null && typeof value === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(value))
            out[k] = interpolateDeep(v, `${context}.${k}`);
        return out;
    }
    return value;
}
function isRaw(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function str(v) {
    return typeof v === 'string';
}
function num(v) {
    return typeof v === 'number' && Number.isFinite(v);
}
function problems() {
    return [];
}
function reqStr(raw, key, ctx, problems) {
    const v = raw[key];
    if (!str(v) || v.length === 0) {
        problems.push(`${ctx}: "${key}" must be a non-empty string`);
        return undefined;
    }
    return v;
}
function optNum(raw, key, ctx, def, min, problems) {
    const v = raw[key];
    if (v === undefined)
        return def;
    if (!num(v) || v < min) {
        problems.push(`${ctx}: "${key}" must be a number >= ${min}`);
        return def;
    }
    return v;
}
function strArray(raw, key, ctx, problems) {
    const v = raw[key];
    if (v === undefined)
        return [];
    if (!Array.isArray(v) || !v.every(str)) {
        problems.push(`${ctx}: "${key}" must be an array of strings`);
        return [];
    }
    return v;
}
function strMap(raw, key, ctx, problems) {
    const v = raw[key];
    if (v === undefined)
        return {};
    if (!isRaw(v) || !Object.values(v).every(str)) {
        problems.push(`${ctx}: "${key}" must be a map of string -> string`);
        return {};
    }
    return v;
}
function rateLimit(raw, ctx, problems) {
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
export function loadConfigFile(path, opts = {}) {
    let text;
    try {
        text = readFileSync(path, 'utf8');
    }
    catch (e) {
        throw new ConfigError([`cannot read config file ${path}: ${e.message}`]);
    }
    let parsed;
    try {
        parsed = parseYaml(text);
    }
    catch (e) {
        throw new ConfigError([`YAML parse error in ${path}: ${e.message}`]);
    }
    if (!isRaw(parsed))
        throw new ConfigError([`${path}: top level must be a mapping`]);
    const interpolated = interpolateDeep(parsed, 'config');
    return validateConfig(interpolated, path, opts);
}
export function validateConfig(raw, source, opts = {}) {
    const p = problems();
    const ctx = (s) => `${source}: ${s}`;
    // ---- gateway name ----
    const gwRaw = raw['gateway'];
    const name = (isRaw(gwRaw) && str(gwRaw['name']) ? gwRaw['name'] : 'mcpgateway');
    // ---- servers ----
    const serversRaw = raw['servers'];
    const servers = [];
    const seenNames = new Set();
    if (!Array.isArray(serversRaw) || serversRaw.length === 0) {
        p.push(ctx('"servers" must be a non-empty array'));
    }
    else {
        serversRaw.forEach((s, i) => {
            const sc = `${ctx(`servers[${i}]`)}`;
            if (!isRaw(s)) {
                p.push(`${sc}: must be a mapping`);
                return;
            }
            const nm = reqStr(s, 'name', sc, p);
            if (nm !== undefined) {
                if (!SERVER_NAME_RE.test(nm))
                    p.push(`${sc}: "name" must match ${SERVER_NAME_RE} (lowercase, used in tool prefixes)`);
                if (seenNames.has(nm))
                    p.push(`${sc}: duplicate server name "${nm}"`);
                seenNames.add(nm);
            }
            const transport = s['transport'];
            if (transport !== 'stdio' && transport !== 'http') {
                p.push(`${sc}: "transport" must be "stdio" or "http"`);
                return;
            }
            const cfg = {
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
                        const resolved = command.includes('/') ? existsSync(command) : commandResolvable(command);
                        if (!resolved)
                            p.push(`${sc}: command "${command}" not found (not on PATH and not an existing path)`);
                    }
                }
                const args = s['args'];
                if (args !== undefined) {
                    if (!Array.isArray(args) || !args.every(str))
                        p.push(`${sc}: "args" must be an array of strings (no shell: argv only)`);
                    else
                        cfg.args = args;
                }
                cfg.env = strMap(s, 'env', sc, p);
                const cwd = s['cwd'];
                if (cwd !== undefined) {
                    if (!str(cwd))
                        p.push(`${sc}: "cwd" must be a string`);
                    else
                        cfg.cwd = cwd;
                }
            }
            else {
                const url = reqStr(s, 'url', sc, p);
                if (url) {
                    let u;
                    try {
                        u = new URL(url);
                    }
                    catch {
                        p.push(`${sc}: "url" is not a valid URL`);
                        u = undefined;
                    }
                    if (u && u.protocol !== 'http:' && u.protocol !== 'https:') {
                        p.push(`${sc}: "url" must be http(s)`);
                    }
                    else if (u && u.protocol === 'http:' && !isLocalhost(u.hostname)) {
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
    const nsRaw = isRaw(raw['namespace']) ? raw['namespace'] : {};
    const strategy = nsRaw['strategy'];
    const namespace = {
        strategy: strategy === undefined ? 'prefix' : strategy,
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
        if (!str(sep) || !/^[A-Za-z0-9_]{1,4}$/.test(sep))
            p.push(ctx('namespace.separator must be 1-4 chars of [A-Za-z0-9_]'));
        else
            namespace.separator = sep;
    }
    namespace.priority = strArray(nsRaw, 'priority', ctx('namespace'), p);
    const mappingsRaw = nsRaw['mappings'];
    if (mappingsRaw !== undefined) {
        if (!isRaw(mappingsRaw) || !Object.values(mappingsRaw).every(str)) {
            p.push(ctx('namespace.mappings must be {toolName: serverName}'));
        }
        else {
            namespace.mappings = mappingsRaw;
            for (const [tool, srv] of Object.entries(namespace.mappings)) {
                if (!seenNames.has(srv))
                    p.push(ctx(`namespace.mappings["${tool}"] references unknown server "${srv}"`));
            }
        }
    }
    const aliasesRaw = nsRaw['aliases'];
    if (aliasesRaw !== undefined) {
        if (!isRaw(aliasesRaw) || !Object.values(aliasesRaw).every(str)) {
            p.push(ctx('namespace.aliases must be {"<server>:<tool>": "<publicName>"}'));
        }
        else {
            for (const [from, to] of Object.entries(aliasesRaw)) {
                if (!/^[^:]+:[^:]+$/.test(from))
                    p.push(ctx(`namespace.aliases key "${from}" must look like "<server>:<tool>"`));
                if (!TOOL_NAME_RE.test(to))
                    p.push(ctx(`namespace.aliases["${from}"] = "${to}" is not a legal MCP tool name`));
                const [srv] = from.split(':');
                if (srv && !seenNames.has(srv))
                    p.push(ctx(`namespace.aliases["${from}"] references unknown server "${srv}"`));
            }
            namespace.aliases = aliasesRaw;
        }
    }
    if (namespace.strategy === 'priority') {
        for (const s of namespace.priority) {
            if (!seenNames.has(s))
                p.push(ctx(`namespace.priority references unknown server "${s}"`));
        }
    }
    // ---- rate limits ----
    const rlRaw = isRaw(raw['rateLimits']) ? raw['rateLimits'] : {};
    const defRaw = rlRaw['default'];
    const defaultRateLimit = defRaw === undefined ? { rps: 10, burst: 20 } : rateLimit(defRaw, ctx('rateLimits.default'), p);
    const perToolRateLimits = {};
    const toolsRaw = rlRaw['tools'];
    if (toolsRaw !== undefined) {
        if (!isRaw(toolsRaw))
            p.push(ctx('rateLimits.tools must be a mapping'));
        else {
            for (const [tool, rule] of Object.entries(toolsRaw)) {
                const r = rateLimit(rule, ctx(`rateLimits.tools["${tool}"]`), p);
                if (r)
                    perToolRateLimits[tool] = r;
            }
        }
    }
    // ---- policy ----
    const polRaw = isRaw(raw['policy']) ? raw['policy'] : {};
    const mode = polRaw['mode'];
    const policy = {
        mode: mode === undefined ? 'enforce' : mode,
        allowTools: strArray(polRaw, 'allowTools', ctx('policy'), p),
        denyTools: strArray(polRaw, 'denyTools', ctx('policy'), p),
        hideTools: strArray(polRaw, 'hideTools', ctx('policy'), p),
        argRules: {},
        responseRedact: strArray(polRaw, 'responseRedact', ctx('policy'), p),
        responseBlock: strArray(polRaw, 'responseBlock', ctx('policy'), p),
        responseWarn: strArray(polRaw, 'responseWarn', ctx('policy'), p),
        scanWindowChars: optNum(polRaw, 'scanWindowChars', ctx('policy'), 65536, 1024, p),
    };
    if (policy.mode !== 'enforce' && policy.mode !== 'observe') {
        p.push(ctx('policy.mode must be enforce|observe'));
        policy.mode = 'enforce';
    }
    if (policy.allowTools.length === 0)
        policy.allowTools = ['*'];
    const argRulesRaw = polRaw['argRules'];
    if (argRulesRaw !== undefined) {
        if (!isRaw(argRulesRaw))
            p.push(ctx('policy.argRules must be a mapping'));
        else {
            for (const [tool, rule] of Object.entries(argRulesRaw)) {
                if (!isRaw(rule)) {
                    p.push(ctx(`policy.argRules["${tool}"] must be {allow?, deny?}`));
                    continue;
                }
                const ar = {};
                for (const k of ['allow', 'deny']) {
                    const v = rule[k];
                    if (v !== undefined) {
                        if (!Array.isArray(v) || !v.every(str))
                            p.push(ctx(`policy.argRules["${tool}"].${k} must be an array of strings (substring matchers)`));
                        else
                            ar[k] = v;
                    }
                }
                policy.argRules[tool] = ar;
            }
        }
    }
    // validate glob patterns compile (they always do — globMatch is ReDoS-safe —
    // but catch typos like unbalanced intent early is unnecessary; skip)
    // ---- auth ----
    const authRaw = isRaw(raw['auth']) ? raw['auth'] : {};
    const authDisabled = authRaw['disabled'] === true;
    const keys = [];
    const keysRaw = authRaw['keys'];
    if (keysRaw !== undefined) {
        if (!Array.isArray(keysRaw))
            p.push(ctx('auth.keys must be an array'));
        else {
            const seenIds = new Set();
            keysRaw.forEach((k, i) => {
                const kc = `${ctx(`auth.keys[${i}]`)}`;
                if (!isRaw(k)) {
                    p.push(`${kc}: must be a mapping`);
                    return;
                }
                const id = reqStr(k, 'id', kc, p);
                const key = reqStr(k, 'key', kc, p);
                if (id && seenIds.has(id))
                    p.push(`${kc}: duplicate key id "${id}"`);
                if (id)
                    seenIds.add(id);
                const scopesRaw = k['scopes'];
                const scopes = [];
                if (scopesRaw === undefined)
                    scopes.push('tools:call', 'tools:list');
                else if (!Array.isArray(scopesRaw) || !scopesRaw.every(str))
                    p.push(`${kc}: "scopes" must be an array of strings`);
                else {
                    for (const s of scopesRaw) {
                        if (!VALID_SCOPES.includes(s))
                            p.push(`${kc}: unknown scope "${s}" (valid: ${VALID_SCOPES.join(', ')})`);
                        else
                            scopes.push(s);
                    }
                }
                if (id && key) {
                    if (key.length < 16)
                        p.push(`${kc}: key is shorter than 16 chars — use a long random secret`);
                    keys.push({ id, key, scopes });
                }
            });
        }
    }
    if (!authDisabled && keys.length === 0) {
        p.push(ctx('auth.keys is empty and auth.disabled is not true — HTTP upstream/admin would accept nobody (or set auth.disabled: true explicitly)'));
    }
    // ---- audit ----
    const audRaw = isRaw(raw['audit']) ? raw['audit'] : {};
    const audit = {
        path: './mcpgateway-audit.jsonl',
        logArgs: true,
        redactKeys: ['token', 'secret', 'password', 'passwd', 'api_key', 'apikey', 'authorization', 'cookie', 'session', 'credential'],
        maxArgsChars: 8192,
        maxSizeMB: 100,
        keepFiles: 5,
    };
    if (audRaw['path'] !== undefined) {
        if (!str(audRaw['path']))
            p.push(ctx('audit.path must be a string'));
        else
            audit.path = audRaw['path'];
    }
    if (audRaw['logArgs'] !== undefined) {
        if (typeof audRaw['logArgs'] !== 'boolean')
            p.push(ctx('audit.logArgs must be boolean'));
        else
            audit.logArgs = audRaw['logArgs'];
    }
    const rk = audRaw['redactKeys'];
    if (rk !== undefined) {
        if (!Array.isArray(rk) || !rk.every(str))
            p.push(ctx('audit.redactKeys must be an array of strings'));
        else
            audit.redactKeys = rk;
    }
    audit.maxArgsChars = optNum(audRaw, 'maxArgsChars', ctx('audit'), 8192, 256, p);
    audit.maxSizeMB = optNum(audRaw, 'maxSizeMB', ctx('audit'), 100, 1, p);
    audit.keepFiles = optNum(audRaw, 'keepFiles', ctx('audit'), 5, 1, p);
    // ---- admin ----
    const admRaw = isRaw(raw['admin']) ? raw['admin'] : {};
    const admin = {
        enabled: true,
        host: '127.0.0.1',
        port: 3001,
        allowPublicAdmin: false,
    };
    if (admRaw['enabled'] !== undefined) {
        if (typeof admRaw['enabled'] !== 'boolean')
            p.push(ctx('admin.enabled must be boolean'));
        else
            admin.enabled = admRaw['enabled'];
    }
    if (admRaw['host'] !== undefined) {
        if (!str(admRaw['host']))
            p.push(ctx('admin.host must be a string'));
        else
            admin.host = admRaw['host'];
    }
    admin.port = optNum(admRaw, 'port', ctx('admin'), 3001, 0, p);
    if (admRaw['allowPublicAdmin'] !== undefined) {
        if (typeof admRaw['allowPublicAdmin'] !== 'boolean')
            p.push(ctx('admin.allowPublicAdmin must be boolean'));
        else
            admin.allowPublicAdmin = admRaw['allowPublicAdmin'];
    }
    if (admin.enabled && isPublicBind(admin.host) && !admin.allowPublicAdmin) {
        p.push(ctx(`admin.host "${admin.host}" is public but admin.allowPublicAdmin is not true — refusing (bind 127.0.0.1 or set the flag explicitly)`));
    }
    // ---- upstream ----
    const upRaw = isRaw(raw['upstream']) ? raw['upstream'] : {};
    const stdioRaw = isRaw(upRaw['stdio']) ? upRaw['stdio'] : {};
    const httpRaw = isRaw(upRaw['http']) ? upRaw['http'] : {};
    const upstream = {
        stdio: { enabled: stdioRaw['enabled'] !== undefined ? stdioRaw['enabled'] === true : true },
        http: { enabled: false, host: '127.0.0.1', port: 3000, maxSessions: 128 },
    };
    if (typeof stdioRaw['enabled'] !== 'undefined' && typeof stdioRaw['enabled'] !== 'boolean') {
        p.push(ctx('upstream.stdio.enabled must be boolean'));
    }
    if (httpRaw['enabled'] !== undefined) {
        if (typeof httpRaw['enabled'] !== 'boolean')
            p.push(ctx('upstream.http.enabled must be boolean'));
        else
            upstream.http.enabled = httpRaw['enabled'];
    }
    if (httpRaw['host'] !== undefined) {
        if (!str(httpRaw['host']))
            p.push(ctx('upstream.http.host must be a string'));
        else
            upstream.http.host = httpRaw['host'];
    }
    upstream.http.port = optNum(httpRaw, 'port', ctx('upstream.http'), 3000, 0, p);
    upstream.http.maxSessions = optNum(httpRaw, 'maxSessions', ctx('upstream.http'), 128, 1, p);
    if (!upstream.stdio.enabled && !upstream.http.enabled) {
        p.push(ctx('at least one upstream transport (stdio or http) must be enabled'));
    }
    // ---- global limits ----
    const globalMaxInflight = optNum(raw, 'globalMaxInflight', source, 256, 1, p);
    const maxResultChars = optNum(raw, 'maxResultChars', source, 10_000_000, 1024, p);
    // unknown top-level keys: warn via problems? Panel said warn, not fail.
    // We surface them as warnings through the returned config instead.
    const knownTop = new Set(['gateway', 'servers', 'namespace', 'rateLimits', 'policy', 'auth', 'audit', 'admin', 'upstream', 'globalMaxInflight', 'maxResultChars']);
    const unknownTop = Object.keys(raw).filter((k) => !knownTop.has(k));
    if (unknownTop.length > 0) {
        // non-fatal: attach to stderr at serve time via a thrown-adjacent channel.
        // Simplest: push as a special problem the CLI prints as warning.
        p.push(ctx(`WARNING: unknown top-level keys ignored: ${unknownTop.join(', ')}`));
    }
    // fail on real problems; warnings are prefixed and filtered by the caller.
    const real = p.filter((x) => !x.includes('WARNING'));
    const warnings = p.filter((x) => x.includes('WARNING'));
    if (real.length > 0)
        throw new ConfigError(real);
    const cfg = {
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
        globalMaxInflight,
        maxResultChars,
    };
    cfg.__warnings = warnings;
    return cfg;
}
/** Warnings collected during validation (unknown keys etc.). Non-fatal. */
export function configWarnings(cfg) {
    return cfg.__warnings ?? [];
}
function isLocalhost(host) {
    const h = host.toLowerCase();
    return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h.endsWith('.localhost');
}
function isPublicBind(host) {
    return host === '0.0.0.0' || host === '::';
}
function commandResolvable(command) {
    // bare binary: search PATH manually (no shell — never spawn one for this)
    const pathEnv = process.env['PATH'] ?? '';
    for (const dir of pathEnv.split(pathDelimiter)) {
        if (!dir)
            continue;
        try {
            accessSync(`${dir}/${command}`, constants.X_OK);
            return true;
        }
        catch {
            /* next */
        }
    }
    return false;
}
/** Does this public tool name match any allow/deny-style glob list? Exported for policy use. */
export function matchesAny(patterns, value) {
    return patterns.some((pat) => globMatch(pat, value));
}
// re-export for namespace/policy convenience
export { globMatch };
//# sourceMappingURL=config.js.map