export class NamespaceError extends Error {
    constructor(message) {
        super(message);
        this.name = 'NamespaceError';
    }
}
const NAME_RE = /^[a-zA-Z0-9_-]{1,64}$/;
export function resolveNames(catalogs, cfg) {
    const warnings = [];
    const collisions = [];
    const byOriginal = new Map();
    for (const cat of catalogs) {
        for (const n of cat.names) {
            if (!NAME_RE.test(n)) {
                warnings.push(`server "${cat.server}" exposes illegal name "${n}" — skipped`);
                continue;
            }
            const group = byOriginal.get(n) ?? [];
            group.push(cat.server);
            byOriginal.set(n, group);
        }
    }
    const firstSeenOrder = [];
    for (const cat of catalogs)
        if (!firstSeenOrder.includes(cat.server))
            firstSeenOrder.push(cat.server);
    const priorityRank = (server) => {
        const i = cfg.priority.indexOf(server);
        if (i !== -1)
            return i;
        return cfg.priority.length + firstSeenOrder.indexOf(server);
    };
    const assigned = new Map();
    for (const [origName, servers] of byOriginal) {
        if (servers.length === 1) {
            assigned.set(`${servers[0]}\0${origName}`, origName);
            continue;
        }
        const sorted = [...servers].sort((a, b) => priorityRank(a) - priorityRank(b));
        if (cfg.strategy === 'prefix') {
            const resolvedAs = sorted.map((s) => `${s}${cfg.separator}${origName}`);
            collisions.push({ originalName: origName, servers: sorted, strategy: 'prefix', resolvedAs, shadowed: [] });
            sorted.forEach((s, i) => assigned.set(`${s}\0${origName}`, resolvedAs[i]));
        }
        else if (cfg.strategy === 'priority') {
            const winner = sorted[0];
            const losers = sorted.slice(1);
            const resolvedAs = [origName, ...losers.map((s) => `${s}${cfg.separator}${origName}`)];
            collisions.push({ originalName: origName, servers: sorted, strategy: 'priority', resolvedAs, shadowed: losers, winner });
            warnings.push(`collision on "${origName}": "${winner}" keeps the bare name; shadowed: ${losers.join(', ')} (reachable as prefixed names)`);
            assigned.set(`${winner}\0${origName}`, origName);
            for (const s of losers)
                assigned.set(`${s}\0${origName}`, `${s}${cfg.separator}${origName}`);
        }
        else {
            const winner = cfg.mappings[origName];
            if (winner === undefined || !servers.includes(winner)) {
                throw new NamespaceError(`collision on "${origName}" (servers: ${servers.join(', ')}) has no namespace.mappings entry — ` +
                    `add 'mappings: {"${origName}": "<winning-server>"}' or switch strategy`);
            }
            const losers = sorted.filter((s) => s !== winner);
            const resolvedAs = [origName, ...losers.map((s) => `${s}${cfg.separator}${origName}`)];
            collisions.push({ originalName: origName, servers: sorted, strategy: 'explicit', resolvedAs, shadowed: losers, winner });
            assigned.set(`${winner}\0${origName}`, origName);
            for (const s of losers)
                assigned.set(`${s}\0${origName}`, `${s}${cfg.separator}${origName}`);
        }
    }
    // Aliases override the strategy assignment.
    for (const [from, to] of Object.entries(cfg.aliases)) {
        const sepIdx = from.indexOf(':');
        const srv = from.slice(0, sepIdx);
        const orig = from.slice(sepIdx + 1);
        const key = `${srv}\0${orig}`;
        if (!assigned.has(key)) {
            throw new NamespaceError(`namespace.aliases["${from}"]: no such tool (server "${srv}" has no tool "${orig}")`);
        }
        assigned.set(key, to);
    }
    // Global validation: uniqueness + legality of every public name.
    const seenPublic = new Map();
    for (const [key, publicName] of assigned) {
        if (!NAME_RE.test(publicName)) {
            const [srv, orig] = key.split('\0');
            throw new NamespaceError(`public name "${publicName}" for ${srv}:${orig} is illegal (names must match ^[a-zA-Z0-9_-]{1,64}$) — ` +
                `shorten the server name or add an alias`);
        }
        const prev = seenPublic.get(publicName);
        if (prev !== undefined) {
            const [srv, orig] = key.split('\0');
            const [psrv, porig] = prev.split('\0');
            throw new NamespaceError(`public name collision: "${publicName}" would name both ${psrv}:${porig} and ${srv}:${orig} — ` +
                `add namespace.aliases entries to disambiguate`);
        }
        seenPublic.set(publicName, key);
    }
    return { assigned, collisions, warnings };
}
// ---------------------------------------------------------------------------
// Tool-specific wrapper (keeps descriptions + schemas attached)
// ---------------------------------------------------------------------------
export function buildNamespace(catalogs, cfg) {
    const nameCatalogs = catalogs.map((c) => ({ server: c.server, names: c.tools.map((t) => t.name) }));
    const { assigned, collisions, warnings } = resolveNames(nameCatalogs, cfg);
    const toolLookup = new Map();
    for (const cat of catalogs) {
        for (const t of cat.tools)
            toolLookup.set(`${cat.server}\0${t.name}`, t);
    }
    const tools = [];
    const byPublicName = new Map();
    for (const [key, publicName] of assigned) {
        const [srv, orig] = key.split('\0');
        const tool = toolLookup.get(key);
        if (tool === undefined)
            continue; // skipped illegal name
        const entry = {
            name: publicName,
            publicName,
            server: srv,
            originalName: orig,
            description: tool.description,
            inputSchema: tool.inputSchema,
        };
        tools.push(entry);
        byPublicName.set(publicName, entry);
    }
    tools.sort((a, b) => a.publicName.localeCompare(b.publicName));
    return { tools, byPublicName, collisions, warnings };
}
//# sourceMappingURL=namespace.js.map