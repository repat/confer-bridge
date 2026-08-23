#!/usr/bin/env node

/**
 * Produce a shareable HAR inventory without copying request/response values.
 * It intentionally reports only methods, normalized routes, header names, and
 * JSON field names/types/serialized lengths.
 */
import { readFile } from 'node:fs/promises';

const harPath = process.argv[2];
if (!harPath) {
  console.error('Usage: npm run analyze:har -- /absolute/path/to/capture.har');
  process.exit(1);
}

const secretHeader = /^(authorization|cookie|set-cookie|x-api-key|proxy-authorization)$/i;
const uuid = /\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=\/|$)/gi;

function normalizeUrl(rawUrl) {
  const url = new URL(rawUrl);
  return `${url.origin}${url.pathname.replace(uuid, '/{id}')}`;
}

function safeJsonShape(text) {
  if (!text) return '—';
  try {
    const value = JSON.parse(text);
    if (Array.isArray(value)) return `array (${value.length})`;
    if (value && typeof value === 'object') {
      return Object.entries(value)
        .map(([key, field]) => {
          const type = Array.isArray(field) ? 'array' : typeof field;
          const size = typeof field === 'string' ? field.length : JSON.stringify(field).length;
          return `${key}:${type}:${size}`;
        })
        .sort()
        .join(', ');
    }
    return typeof value;
  } catch {
    return `non-JSON (${text.length} chars)`;
  }
}

const document = JSON.parse(await readFile(harPath, 'utf8'));
const entries = document?.log?.entries;
if (!Array.isArray(entries)) throw new Error('Not a HAR 1.2 file with log.entries.');

const routes = new Map();
for (const entry of entries) {
  const key = `${entry.request.method} ${normalizeUrl(entry.request.url)}`;
  const existing = routes.get(key) ?? {
    method: entry.request.method,
    url: normalizeUrl(entry.request.url),
    count: 0,
    statuses: new Set(),
    requestShapes: new Set(),
    responseShapes: new Set(),
    headerNames: new Set(),
  };
  existing.count += 1;
  existing.statuses.add(entry.response.status);
  existing.requestShapes.add(safeJsonShape(entry.request.postData?.text));
  existing.responseShapes.add(safeJsonShape(entry.response.content?.text));
  for (const header of entry.request.headers ?? []) {
    existing.headerNames.add(secretHeader.test(header.name) ? `${header.name} (redacted)` : header.name);
  }
  routes.set(key, existing);
}

console.log('# Sanitized HAR inventory\n');
console.log(`- Entries: ${entries.length}`);
console.log(`- HAR creator: ${document.log.creator?.name ?? 'unknown'} ${document.log.creator?.version ?? ''}`);
console.log('- Values, cookies, authorization material, and body contents are deliberately omitted.\n');
console.log('| Method | Normalized route | Calls | Statuses | Request shape | Response shape | Request header names |');
console.log('| --- | --- | ---: | --- | --- | --- | --- |');
for (const route of [...routes.values()].sort((a, b) => a.url.localeCompare(b.url) || a.method.localeCompare(b.method))) {
  console.log(`| ${route.method} | ${route.url} | ${route.count} | ${[...route.statuses].sort().join(', ')} | ${[...route.requestShapes].sort().join('<br>')} | ${[...route.responseShapes].sort().join('<br>')} | ${[...route.headerNames].sort().join(', ')} |`);
}
