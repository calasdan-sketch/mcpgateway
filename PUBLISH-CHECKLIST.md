# Publish checklist for mcpgateway (plain words)

Do not do any of this until you have read it once. Nothing here has been run for you: no upload, no tag, no push.

## What to release

Version **0.3.0**. The name `mcpgateway` was not on the npm registry when checked (2026-11-08), so this is the first
upload and there is nothing older to break. Author shown to the world: `Calas Automations Inc.`

## Check first

1. The repository is private. The package says nothing about a GitHub address on purpose. If you later make it public, add
   `repository`, `homepage` and `bugs` lines to `package.json` yourself.
2. Make sure the name is still free: `npm view mcpgateway version` should say "404 Not Found". If it prints a number, stop:
   somebody else took the name.
3. Be signed in to npm yourself: `npm whoami` should print your account name.
4. From the project folder, run the tests: `npm test` (expect 0 failures).
5. Look at what would be uploaded: `npm pack --dry-run`. You should see about 34 files, all under `dist/src`, plus
   README, LICENSE, CHANGELOG, `package.json` and `mcpgateway.example.yaml`. If you see `tests` or `.map` files, stop.
6. Try the real package once on this machine: `npm pack`, then `npm install -g ./mcpgateway-0.3.0.tgz`, then
   `mcpgateway --version` (prints 0.3.0) and `mcpgateway --help` (last line says "Maintained by Calas Automations Inc.").

## The upload (this step is yours)

```
npm publish
```

Optionally first `npm publish --dry-run` to see it without uploading. npm will ask for a one-time code if your account
uses two-step sign-in. After uploading, open a clean folder and run `npx mcpgateway --version` to confirm.

## Afterwards

- In the README, change the Install section to `npm install -g mcpgateway`.
- Version numbers: next fixes are 0.3.1; new features 0.4.0.
- Not tested: Windows and macOS. Say so if anyone asks.
