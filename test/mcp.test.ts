import { test, expect, describe, afterAll } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tmp = mkdtempSync(join(tmpdir(), "vibecheck-mcp-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));
writeFileSync(join(tmp, "server.ts"), 'app.post("/run", (req, res) => { eval(req.body.code); });');

describe("AC6.1 MCP stdio server", () => {
  test("initialize, tools/list, tools/call=scan over JSON-RPC", async () => {
    const proc = Bun.spawn(["bun", "src/cli.ts", "mcp"], { cwd: process.cwd(), stdin: "pipe", stdout: "pipe", stderr: "inherit" });
    const reqs = [
      { jsonrpc: "2.0", id: 1, method: "initialize" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "scan", arguments: { dir: tmp } } },
    ];
    for (const r of reqs) proc.stdin.write(`${JSON.stringify(r)}\n`);
    await proc.stdin.flush();

    const reader = proc.stdout.getReader();
    const dec = new TextDecoder();
    const byId = new Map<number, any>();
    let buf = "";
    const deadline = Date.now() + 8000;
    try {
      while (byId.size < 3 && Date.now() < deadline) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value);
        let nl: number;
        while ((nl = buf.indexOf("\n")) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (line) { const o = JSON.parse(line); if (typeof o.id === "number") byId.set(o.id, o); }
        }
      }
    } finally {
      proc.kill();
    }

    expect(byId.get(1)?.result?.serverInfo?.name).toBe("vibecheck");
    expect(byId.get(2)?.result?.tools?.[0]?.name).toBe("scan");
    const text = byId.get(3)?.result?.content?.[0]?.text as string;
    const scan = JSON.parse(text) as { findings: { ruleId: string }[] };
    expect(scan.findings.some((f) => f.ruleId === "VC-RCE-EVAL")).toBe(true);
  });
});
