'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

for (const key of ['STS_OPENCODE_V1_BIN', 'STS_OPENCODE_V2_BIN']) {
  if (!process.env[key] || !fs.existsSync(process.env[key])) {
    process.stderr.write(`${key} must name an installed executable; host acceptance cannot be skipped.\n`);
    process.exit(1);
  }
}
const result = spawnSync(process.execPath, ['--test', 'test/opencode-dual-smoke.test.mjs'], {
  cwd: path.resolve(__dirname, '..'), stdio: 'inherit', windowsHide: true
});
if (result.error) process.stderr.write(`${result.error.message}\n`);
process.exitCode = result.status ?? 1;
