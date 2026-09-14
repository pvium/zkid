import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { ensureCircuitJson } from '../src/config.js';

const here = dirname(fileURLToPath(import.meta.url));

test('the committed .gz inflates to a circuit bb and noir_js can load, matching the full build', () => {
  const gz = join(here, '..', 'circuit', 'pvium_identity.json.gz');
  const dir = mkdtempSync(join(tmpdir(), 'pvium-circuit-'));
  writeFileSync(join(dir, 'pvium_identity.json.gz'), readFileSync(gz));
  const cfg = { circuitJson: join(dir, 'pvium_identity.json') } as Parameters<typeof ensureCircuitJson>[0];
  ensureCircuitJson(cfg);
  assert.ok(existsSync(cfg.circuitJson));
  const slim = JSON.parse(readFileSync(cfg.circuitJson, 'utf8'));
  assert.deepEqual(Object.keys(slim).sort(), ['abi', 'bytecode', 'hash', 'noir_version']);
  const full = JSON.parse(readFileSync(join(here, '..', 'circuit', 'pvium_identity.json'), 'utf8'));
  assert.equal(slim.bytecode, full.bytecode);
  assert.equal(slim.hash, full.hash);
  ensureCircuitJson(cfg); // idempotent
});

test('a missing archive is reported clearly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pvium-circuit-'));
  assert.throws(() => ensureCircuitJson({ circuitJson: join(dir, 'x.json') } as never), /run yarn sync/);
  writeFileSync(join(dir, 'y.json.gz'), gzipSync('{"bytecode":"","abi":{},"hash":"0","noir_version":"t"}'));
  ensureCircuitJson({ circuitJson: join(dir, 'y.json') } as never);
  assert.ok(existsSync(join(dir, 'y.json')));
});
