/** Labeled benchmark cases. `expect` = the core (high/medium-confidence, non-advisory) rule ids that
 *  SHOULD fire. Safe cases expect []. Secrets/env are covered by unit tests, not here. */
export interface Case { name: string; rel: string; code: string; expect: string[] }

export const CORPUS: Case[] = [
  // RCE
  { name: "rce-eval-tainted", rel: "a.ts", code: "app.post('/r',(req,res)=>{ eval(req.body.code); })", expect: ["VC-RCE-EVAL"] },
  { name: "rce-eval-literal", rel: "a.ts", code: "eval('1 + 1')", expect: [] },
  { name: "rce-eval-var", rel: "a.ts", code: "function run(x){ return eval(x); }", expect: ["VC-RCE-EVAL"] },
  { name: "rce-newfn-tainted", rel: "a.ts", code: "const f = new Function(req.query.body);", expect: ["VC-RCE-EVAL"] },
  { name: "rce-cp-tainted-var", rel: "a.ts", code: "const cmd = req.body.cmd; execSync(cmd);", expect: ["VC-RCE-CHILD-PROCESS"] },
  { name: "rce-cp-member-tainted", rel: "a.ts", code: "child_process.exec(`ping ${req.query.host}`);", expect: ["VC-RCE-CHILD-PROCESS"] },
  { name: "rce-cp-literal", rel: "a.ts", code: "execSync('ls -la');", expect: [] },
  { name: "rce-orm-exec-safe", rel: "a.ts", code: "const u = await User.find({}).exec();", expect: [] },
  { name: "rce-regexp-exec-safe", rel: "a.ts", code: "const m = /a+b/.exec(input);", expect: [] },
  // SQLi (the v0.1 blind spot: abstracted raw APIs + taint)
  { name: "sqli-knex-raw-taint", rel: "a.ts", code: "knex.raw(req.query.q);", expect: ["VC-SQLI"] },
  { name: "sqli-prisma-unsafe-var", rel: "a.ts", code: "const q = req.query.id; prisma.$queryRawUnsafe(q);", expect: ["VC-SQLI"] },
  { name: "sqli-query-template-taint", rel: "a.ts", code: "db.query(`SELECT * FROM u WHERE id = ${req.params.id}`);", expect: ["VC-SQLI"] },
  { name: "sqli-sequelize-taint", rel: "a.ts", code: "sequelize.query('SELECT * FROM u WHERE n=' + req.body.name);", expect: ["VC-SQLI"] },
  { name: "sqli-parameterized-safe", rel: "a.ts", code: "db.query('SELECT * FROM u WHERE id = $1', [req.query.id]);", expect: [] },
  { name: "sqli-tagged-template-safe", rel: "a.ts", code: "const r = sql`SELECT * FROM u WHERE id = ${id}`;", expect: [] },
  { name: "sqli-numeric-sanitized-safe", rel: "a.ts", code: "const id = Number(req.query.id); db.query(`SELECT * FROM u WHERE id = ${id}`);", expect: [] },
  { name: "sqli-validated-safe", rel: "a.ts", code: "const id = schema.parse(req.query.id); db.query(`SELECT ${id}`);", expect: [] },
  // XSS
  { name: "xss-react-taint", rel: "a.tsx", code: "const el = <div dangerouslySetInnerHTML={{ __html: req.query.html }} />;", expect: ["VC-XSS-REACT"] },
  { name: "xss-react-literal-safe", rel: "a.tsx", code: "const el = <div dangerouslySetInnerHTML={{ __html: '<b>ok</b>' }} />;", expect: [] },
  { name: "xss-dom-taint", rel: "a.ts", code: "node.innerHTML = req.body.html;", expect: ["VC-XSS-DOM"] },
  { name: "xss-dom-literal-safe", rel: "a.ts", code: "node.innerHTML = '<b>static</b>';", expect: [] },
  { name: "xss-docwrite-taint", rel: "a.ts", code: "document.write(location.search);", expect: ["VC-XSS-DOM"] },
  // SSRF / path / redirect (taint-backed, high only)
  { name: "ssrf-taint", rel: "a.ts", code: "fetch(req.query.url);", expect: ["VC-SSRF"] },
  { name: "ssrf-axios-taint", rel: "a.ts", code: "axios.get(req.body.callback);", expect: ["VC-SSRF"] },
  { name: "ssrf-const-safe", rel: "a.ts", code: "fetch('https://api.example.com/v1');", expect: [] },
  { name: "path-traversal-taint", rel: "a.ts", code: "fs.readFile(path.join(dir, req.query.file), cb);", expect: ["VC-PATH-TRAVERSAL"] },
  { name: "path-const-safe", rel: "a.ts", code: "fs.readFileSync('./config.json');", expect: [] },
  { name: "redirect-taint", rel: "a.ts", code: "res.redirect(req.query.next);", expect: ["VC-OPEN-REDIRECT"] },
  { name: "redirect-const-safe", rel: "a.ts", code: "res.redirect('/dashboard');", expect: [] },
  // CORS / JWT / cookie (AST of options)
  { name: "cors-wildcard-creds", rel: "a.ts", code: "app.use(cors({ origin: '*', credentials: true }));", expect: ["VC-CORS-WILDCARD"] },
  { name: "cors-wildcard", rel: "a.ts", code: "cors({ origin: '*' });", expect: ["VC-CORS-WILDCARD"] },
  { name: "cors-allowlist-safe", rel: "a.ts", code: "cors({ origin: 'https://app.example.com', credentials: true });", expect: [] },
  { name: "jwt-none", rel: "a.ts", code: "jwt.verify(token, secret, { algorithms: ['none'] });", expect: ["VC-JWT-NONE"] },
  { name: "jwt-unpinned", rel: "a.ts", code: "jwt.verify(token, secret);", expect: ["VC-JWT-UNPINNED"] },
  { name: "jwt-pinned-safe", rel: "a.ts", code: "jwt.verify(token, secret, { algorithms: ['HS256'] });", expect: [] },
  { name: "cookie-insecure", rel: "a.ts", code: "res.cookie('session', v, { httpOnly: true });", expect: ["VC-COOKIE-INSECURE"] },
  { name: "cookie-secure-safe", rel: "a.ts", code: "res.cookie('session', v, { httpOnly: true, secure: true, sameSite: 'lax' });", expect: [] },
  { name: "cookie-nonauth-safe", rel: "a.ts", code: "res.cookie('theme', 'dark');", expect: [] },
  // misc config
  { name: "stack-exposure", rel: "a.ts", code: "app.use((e,req,res,n)=>{ res.send(e.stack); });", expect: ["VC-STACK-EXPOSURE"] },
  { name: "stack-safe", rel: "a.ts", code: "res.status(500).send('Internal error');", expect: [] },
  { name: "nextpublic-secret", rel: "a.ts", code: "const k = process.env.NEXT_PUBLIC_API_SECRET;", expect: ["VC-NEXT-PUBLIC-SECRET"] },
  { name: "nextpublic-anon-safe", rel: "a.ts", code: "const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;", expect: [] },
  { name: "supabase-service-role", rel: "a.ts", code: "createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);", expect: ["VC-SUPABASE-SERVICE-ROLE"] },
];
