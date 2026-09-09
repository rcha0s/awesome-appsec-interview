#!/usr/bin/env node
// Renders every ```mermaid block under docs/ with mermaid.render(), the same
// call docs/javascripts/mermaid-theme.mjs makes in the browser. A static
// `mkdocs build` never executes mermaid.js, so a malformed diagram (e.g. a
// semicolon inside sequence-diagram message/note text, which mermaid treats
// as a statement separator even mid-sentence) produces zero build warnings
// and only shows up as "Diagram failed to render." on the live page. This
// script is the only thing in the repo that actually catches that class of
// bug before it ships.
//
// Uses the `mermaid` package pulled in by @mermaid-js/mermaid-cli (see
// package.json) so the rendered version tracks whatever mermaid-cli last
// pinned, and mermaid-theme.mjs should be kept on a close version too.
//
// Exit code 0 = every diagram rendered. Exit code 1 = at least one failed
// (details printed to stdout); tests/test_site.py shells out to this and
// asserts on the exit code.

import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { createRequire } from "node:module";
import puppeteer from "puppeteer";

const require = createRequire(import.meta.url);
const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const DOCS_DIR = path.join(REPO_ROOT, "docs");
const MERMAID_DIST_DIR = path.dirname(require.resolve("mermaid/dist/mermaid.esm.min.mjs"));
const MERMAID_ENTRY = "mermaid.esm.min.mjs";

// Mirrors the mermaid.initialize() call in docs/javascripts/mermaid-theme.mjs
// (theme colors omitted -- irrelevant to whether a diagram parses/renders).
// Keep the structural options (flowchart.htmlLabels, sequence font sizes) in
// sync with that file if it changes.
const MERMAID_INIT_CONFIG = {
  startOnLoad: false,
  theme: "base",
  fontFamily: "Inter, sans-serif",
  sequence: { actorFontSize: 15, messageFontSize: 15, noteFontSize: 14 },
  flowchart: { htmlLabels: true, curve: "basis" },
};

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.isFile() && entry.name.endsWith(".md")) out.push(full);
  }
  return out;
}

function extractDiagrams(file) {
  const content = fs.readFileSync(file, "utf8");
  const re = /```mermaid\r?\n([\s\S]*?)```/g;
  const out = [];
  let m;
  while ((m = re.exec(content)) !== null) {
    const line = content.slice(0, m.index).split(/\r?\n/).length;
    out.push({ file, line, source: m[1] });
  }
  return out;
}

function startMermaidServer() {
  const MIME = { ".mjs": "text/javascript", ".js": "text/javascript", ".map": "application/json", ".html": "text/html" };
  const root = path.resolve(MERMAID_DIST_DIR);
  const server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(req.url.split("?")[0]);
    if (urlPath === "/" || urlPath === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<!doctype html><html><head><meta charset=\"utf-8\"></head><body></body></html>");
      return;
    }
    // Serve the whole mermaid dist directory: the entry module lazy-loads
    // per-diagram-type chunks (dist/chunks/mermaid.esm.min/*.mjs) at runtime.
    const filePath = path.resolve(root, "." + urlPath);
    if (!filePath.startsWith(root) || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      res.writeHead(404);
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": MIME[path.extname(filePath)] || "application/octet-stream" });
    fs.createReadStream(filePath).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

async function main() {
  const files = walk(DOCS_DIR);
  const diagrams = files.flatMap(extractDiagrams);
  console.log(`Checking ${diagrams.length} mermaid diagram(s) across ${files.length} markdown file(s)...`);

  const server = await startMermaidServer();
  const port = server.address().port;

  // --no-sandbox is required on GitHub Actions' Ubuntu runners, which
  // restrict unprivileged user namespaces; acceptable here since this is a
  // short-lived CI job rendering the repo's own trusted content, not a
  // multi-tenant service.
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "load" });

  await page.evaluate(
    async ({ url, config }) => {
      const mod = await import(url);
      window.mermaid = mod.default;
      window.mermaid.initialize(config);
    },
    { url: `http://127.0.0.1:${port}/${MERMAID_ENTRY}`, config: MERMAID_INIT_CONFIG }
  );

  const results = [];
  for (let i = 0; i < diagrams.length; i++) {
    const d = diagrams[i];
    const result = await page.evaluate(
      async ({ id, source }) => {
        try {
          await window.mermaid.render(id, source);
          return { ok: true };
        } catch (e) {
          return { ok: false, error: String((e && e.message) || e) };
        }
      },
      { id: `diagram-check-${i}`, source: d.source }
    );
    results.push({ ...d, ...result });
  }

  await browser.close();
  server.close();

  const failures = results.filter((r) => !r.ok);
  if (failures.length === 0) {
    console.log(`All ${diagrams.length} diagram(s) render cleanly.`);
    process.exit(0);
  }

  console.log(`\n${failures.length} diagram(s) failed to render:\n`);
  for (const f of failures) {
    const rel = path.relative(REPO_ROOT, f.file).replace(/\\/g, "/");
    console.log(`FAIL  ${rel}:${f.line}`);
    console.log(`      ${f.error.split("\n")[0]}`);
  }
  process.exit(1);
}

main().catch((err) => {
  console.error("check-mermaid-diagrams.mjs crashed:", err);
  process.exit(1);
});
