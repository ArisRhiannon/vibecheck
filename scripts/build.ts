/** Build a Node-runnable distribution: bundle the Bun/TS sources for `target: node` (resolves
 *  extensionless imports + bundles @babel), copy the python/go analyzers beside the bundle (they are
 *  loaded via import.meta.url), and give the CLI a `node` shebang. */
import { copyFileSync, readFileSync, writeFileSync, chmodSync, rmSync, mkdirSync } from "node:fs";

rmSync("dist", { recursive: true, force: true });
mkdirSync("dist", { recursive: true });

const out = await Bun.build({
  entrypoints: ["src/cli.ts", "src/index.ts"],
  outdir: "dist",
  target: "node",
  format: "esm",
});
if (!out.success) { console.error(out.logs); process.exit(1); }

// The analyzers are data files loaded at runtime via `new URL("./python.py", import.meta.url)`.
copyFileSync("src/python.py", "dist/python.py");
copyFileSync("src/go.go", "dist/go.go");

// Replace the dev (`bun`) shebang on the CLI with a portable `node` one.
const cliPath = "dist/cli.js";
let cli = readFileSync(cliPath, "utf8");
if (cli.startsWith("#!")) cli = cli.slice(cli.indexOf("\n") + 1);
writeFileSync(cliPath, `#!/usr/bin/env node\n${cli}`);
chmodSync(cliPath, 0o755);
console.log("build ok -> dist/cli.js, dist/index.js, dist/python.py, dist/go.go");
