/**
 * Every committed vector, with the manifest checked before any of them is read as data.
 *
 * The directory is enumerated rather than listed here: a `*.json` vector with no handler fails the
 * suite, so "every vector" is a property the run enforces and not a claim its author makes.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { HANDLERS } from "./handlers.ts";
import { VECTORS_DIR, loadVector, vectorFiles } from "./support.ts";

type ManifestEntry = { sha256: string; mode: string; file: string };

function readManifest(): ManifestEntry[] {
  const text = readFileSync(path.join(VECTORS_DIR, "MANIFEST.sha256"), "utf8");
  return text
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => {
      const parts = line.split(/\s+/);
      assert.equal(parts.length, 3, `manifest line is not "<sha256> <mode> <file>": ${line}`);
      return { sha256: parts[0]!, mode: parts[1]!, file: parts[2]! };
    });
}

test("MANIFEST.sha256 covers the vector directory and every digest matches", () => {
  const manifest = readManifest();
  assert.ok(manifest.length > 0, "empty manifest");

  for (const entry of manifest) {
    const full = path.join(VECTORS_DIR, entry.file);
    const digest = createHash("sha256").update(readFileSync(full)).digest("hex");
    assert.equal(digest, entry.sha256, `${entry.file}: content does not match the manifest`);
    const mode = (statSync(full).mode & 0o7777).toString(8).padStart(4, "0");
    assert.equal(mode, entry.mode, `${entry.file}: mode does not match the manifest`);
  }

  const listed = new Set(manifest.map((e) => e.file));
  const present = readdirSync(VECTORS_DIR).filter((f) => f !== "MANIFEST.sha256");
  for (const file of present) {
    assert.ok(listed.has(file), `${file} is in the directory and not in the manifest`);
  }
});

test("every *.json vector has a handler", () => {
  const files = vectorFiles();
  const missing = files.map((f) => f.replace(/\.json$/, "")).filter((id) => HANDLERS[id] === undefined);
  assert.deepEqual(missing, [], `vectors with no handler: ${missing.join(", ")}`);

  const extra = Object.keys(HANDLERS).filter((id) => !files.includes(`${id}.json`));
  assert.deepEqual(extra, [], `handlers for vectors that are not in the directory: ${extra.join(", ")}`);

  assert.equal(files.length, 32, `expected 32 committed *.json vectors, found ${files.length}`);
});

for (const file of vectorFiles()) {
  const id = file.replace(/\.json$/, "");
  test(`${id}: ${loadVector(id).description ?? ""}`.trim(), () => {
    const vector = loadVector(id);
    assert.equal(vector.id, id, "the vector's own id disagrees with its filename");
    const handler = HANDLERS[id];
    assert.ok(handler !== undefined, `no handler for ${id}`);
    handler(vector);
  });
}
