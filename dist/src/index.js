#!/usr/bin/env node
import { main } from './cli.js';
main(process.argv.slice(2)).catch((e) => {
    console.error(`mcpgateway: fatal: ${e.message}`);
    process.exit(1);
});
//# sourceMappingURL=index.js.map