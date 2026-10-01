/**
 * A static file server for the demo, in the runtime the project already requires.
 *
 * No dependency: `npx serve` or a bundler's dev server would each add one, and the demo's whole point
 * at D-124 was that the verifier runs in a browser without new machinery. Node is already needed to
 * build `ts/`, so it serves the result too.
 */
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";

const ROOT = resolve(new URL(".", import.meta.url).pathname);
const PORT = Number(process.env.PORT ?? 8730);
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

createServer(async (req, res) => {
  // Everything is resolved under ROOT and anything that escapes it is refused, so a path with `..`
  // cannot reach the rest of the repository.
  const requested = normalize(decodeURIComponent((req.url ?? "/").split("?")[0]));
  const file = resolve(join(ROOT, requested === "/" ? "index.html" : requested));
  if (!file.startsWith(ROOT + "/") && file !== join(ROOT, "index.html")) {
    res.writeHead(403).end("outside the demo directory");
    return;
  }
  try {
    const body = await readFile(file);
    res.writeHead(200, {
      "content-type": TYPES[extname(file)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end(`not found: ${requested}`);
  }
}).listen(PORT, () => {
  console.log(`demo: http://localhost:${PORT}`);
});
