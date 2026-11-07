/**
 * Real stdio MCP server used by crash-recovery tests and the benchmark.
 * Tools: echo, strict (rejects bad args with InvalidParams), crash (exits).
 * Env FIXTURE_TOOLS=<n> adds n filler tools (for catalog-size benchmarks).
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
// Test switches: hostile stderr, a child that ignores SIGTERM, and its pid on stderr.
if (process.env['FIXTURE_STDERR_ESC'] === '1')
    process.stderr.write('\u001b[31mred\u001b[0m\u001b]0;pwned\u0007 \u202eevil\r\n');
if (process.env['FIXTURE_IGNORE_SIGTERM'] === '1')
    process.on('SIGTERM', () => undefined);
if (process.env['FIXTURE_PRINT_PID'] === '1')
    process.stderr.write(`PID:${process.pid}\n`);
const extra = Number(process.env['FIXTURE_TOOLS'] ?? '0');
const server = new Server({ name: 'fixture', version: '1.0.0' }, { capabilities: { tools: {} } });
const schema = { type: 'object', properties: { text: { type: 'string', description: 'text to echo' } } };
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        { name: 'echo', description: 'Echo text back', inputSchema: schema },
        { name: 'strict', description: 'Rejects every call with InvalidParams', inputSchema: schema },
        { name: 'big', description: 'Returns n characters of text', inputSchema: schema },
        { name: 'crash', description: 'Exits the process', inputSchema: schema },
        ...Array.from({ length: extra }, (_, i) => ({
            name: `filler_${i}`,
            description: `Filler tool number ${i}: performs a realistic-sounding operation on a resource and returns a summary.`,
            inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'resource id' }, verbose: { type: 'boolean' } } },
        })),
    ],
}));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const n = req.params.name;
    if (n === 'crash')
        process.exit(1);
    if (n === 'strict')
        throw new McpError(ErrorCode.InvalidParams, 'bad arguments');
    if (n === 'big')
        return { content: [{ type: 'text', text: 'x'.repeat(Number(req.params.arguments?.n ?? 0)) }] };
    const t = req.params.arguments?.text ?? '';
    return { content: [{ type: 'text', text: n === 'echo' ? t : `ok:${n}` }] };
});
await server.connect(new StdioServerTransport());
//# sourceMappingURL=stdio-server.js.map