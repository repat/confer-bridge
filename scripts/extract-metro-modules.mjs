#!/usr/bin/env node

/**
 * Extract a focused set of raw Metro modules from an application bundle.
 * This is deliberately a capture aid: output belongs under gitignored
 * captures/, never under version-controlled source.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';

const input = process.argv[2];
const output = process.argv[3] ?? 'captures/metro-modules';
if (!input) {
  console.error('Usage: npm run extract:metro -- /absolute/path/to/entry.js [output-directory]');
  process.exit(1);
}

const targets = new Map([
  [1280, 'master-cipher'], [1282, 'encrypting-api-client'], [1283, 'chat-cipher'],
  [1957, 'secure-model-provider'], [1958, 'secure-model-client'], [1959, 'noise-websocket-client'],
  [1971, 'noise-transport-framer'], [2029, 'noise-transport-proto'],
  [2036, 'attestation-validator'], [2037, 'tdx-attestation-validator'], [3823, 'passkey-prf'],
  [3838, 'passkey-master-key'], [3839, 'recovery-key-master-key'],
]);

const bundle = await readFile(input, 'utf8');
const lines = bundle.split(/\r?\n/);
const found = new Map();
for (const line of lines) {
  if (!line.startsWith('__d(')) continue;
  const match = line.match(/\},(\d+),\[[^\n]*\]\);$/);
  if (match && targets.has(Number(match[1]))) found.set(Number(match[1]), line);
}

await mkdir(output, { recursive: true });
for (const [id, label] of targets) {
  const module = found.get(id);
  if (module) await writeFile(resolve(output, `${String(id).padStart(4, '0')}-${label}.js`), `${module}\n`);
}

const missing = [...targets.keys()].filter((id) => !found.has(id));
console.log(`Extracted ${found.size}/${targets.size} modules from ${basename(input)} into ${resolve(output)}.`);
if (missing.length) console.warn(`Missing module IDs (bundle may differ): ${missing.join(', ')}.`);
