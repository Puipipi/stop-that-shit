'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
test('Codex marketplace selects a synchronized self-contained bundle', () => {
  const marketplace = JSON.parse(fs.readFileSync(path.join(root, '.agents/plugins/marketplace.json')));
  assert.deepEqual(marketplace.plugins[0].source, {source: 'local', path: './codex-plugin'});
  const check = spawnSync(process.execPath, ['scripts/build-codex-plugin.cjs', '--check'], {cwd: root, encoding: 'utf8'});
  assert.equal(check.status, 0, check.stderr);
  const bundle = path.join(root, 'codex-plugin');
  assert.ok(fs.existsSync(path.join(bundle, 'LICENSE')));
  const manifest = JSON.parse(fs.readFileSync(path.join(bundle, '.codex-plugin/plugin.json')));
  assert.ok(fs.existsSync(path.join(bundle, manifest.skills)));
  const hooks = JSON.parse(fs.readFileSync(path.join(bundle, manifest.hooks)));
  assert.deepEqual(Object.keys(hooks.hooks).sort(), ['PostToolUse', 'PreToolUse', 'SessionEnd', 'UserPromptSubmit']);
  const dataDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'sts-bundle-'));
  try {
    const input = JSON.stringify({hook_event_name: 'UserPromptSubmit', session_id: 'bundle-test', prompt: 'hello'});
    const result = spawnSync(process.execPath, ['hooks/stop-that-shit.cjs'], {cwd: bundle, input, encoding: 'utf8', env: {...process.env, PLUGIN_DATA: dataDir}});
    assert.equal(result.status, 0, result.stderr);
  } finally { fs.rmSync(dataDir, {recursive: true, force: true}); }
});

test('bundle check rejects missing, modified, and extra files without changing the bundle', () => {
  const temp = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'sts-bundle-check-'));
  try {
    for (const entry of ['scripts/build-codex-plugin.cjs', '.codex-plugin', 'hooks', 'src', 'package.json', 'LICENSE', 'skills', 'assets']) {
      const dest = path.join(temp, entry);
      fs.mkdirSync(path.dirname(dest), {recursive: true});
      fs.cpSync(path.join(root, entry), dest, {recursive: true});
    }
    const run = (...args) => spawnSync(process.execPath, ['scripts/build-codex-plugin.cjs', ...args], {cwd: temp, encoding: 'utf8'});
    assert.equal(run().status, 0);
    const file = path.join(temp, 'codex-plugin', 'LICENSE');
    const original = fs.readFileSync(file);
    fs.unlinkSync(file);
    assert.notEqual(run('--check').status, 0);
    fs.writeFileSync(file, original);
    fs.appendFileSync(file, 'drift');
    assert.notEqual(run('--check').status, 0);
    fs.writeFileSync(file, original);
    fs.writeFileSync(path.join(temp, 'codex-plugin', 'extra'), 'extra');
    assert.notEqual(run('--check').status, 0);
    assert.equal(fs.readFileSync(path.join(temp, 'codex-plugin', 'extra'), 'utf8'), 'extra');
  } finally { fs.rmSync(temp, {recursive: true, force: true}); }
});
