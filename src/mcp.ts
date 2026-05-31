import { scanProject, countBySeverity } from "./engine";

interface RpcReq { jsonrpc?: string; id?: number | string | null; method?: string; params?: { name?: string; arguments?: { dir?: string; includeAll?: boolean } } }

const TOOLS = [{
  name: "scan",
  description: "Scan a project directory for vibe-coding security / ship-readiness issues (offline, no AI). Returns high-confidence (taint-backed) findings as JSON by default; pass includeAll:true for medium/review too. Run before declaring a coding task done.",
  inputSchema: { type: "object", properties: { dir: { type: "string", description: "project directory to scan (default '.')" }, includeAll: { type: "boolean", description: "include medium/review-confidence findings (default false)" } } },
}];

function send(msg: unknown): void {
  process.stdout.write(`${JSON.stringify(msg)}\n`);
}

function handle(req: RpcReq): void {
  const id = req.id ?? null;
  switch (req.method) {
    case "initialize":
      send({ jsonrpc: "2.0", id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "vibecheck", version: "0.1.0" } } });
      return;
    case "tools/list":
      send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
      return;
    case "tools/call": {
      if (req.params?.name !== "scan") { send({ jsonrpc: "2.0", id, error: { code: -32602, message: `unknown tool: ${req.params?.name}` } }); return; }
      try {
        const r = scanProject(req.params.arguments?.dir ?? ".");
        const findings = req.params.arguments?.includeAll ? r.findings : r.findings.filter((f) => f.confidence === "high");
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: JSON.stringify({ findings, counts: countBySeverity(findings) }) }], isError: false } });
      } catch (e) {
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `error: ${(e as Error).message}` }], isError: true } });
      }
      return;
    }
    default:
      if (req.id !== undefined && req.id !== null) send({ jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${req.method}` } });
  }
}

/** Start the MCP stdio server (newline-delimited JSON-RPC). */
export function startMcp(): void {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        handle(JSON.parse(line) as RpcReq);
      } catch {
        /* ignore malformed line */
      }
    }
  });
  process.stdin.on("end", () => process.exit(0));
}
