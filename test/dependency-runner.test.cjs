'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { handleHook } = require('../src/hook-policy.cjs');

test('controlled runner pins approved directory, argv and consumes ticket once', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-runner-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dataDir = path.join(root, 'data');
  const bin = path.join(root, 'bin');
  const entry = path.join(bin, 'node_modules', 'pnpm', 'bin', 'pnpm.cjs');
  const target = path.join(root, 'target');
  const other = path.join(root, 'other');
  fs.mkdirSync(path.dirname(entry), { recursive: true });
  fs.mkdirSync(target);
  fs.mkdirSync(other);
  fs.writeFileSync(entry, "require('node:fs').writeFileSync('receipt.json',JSON.stringify({cwd:process.cwd(),args:process.argv.slice(2)}))");
  const originalPath = process.env.PATH;
  process.env.PATH = `${bin}${path.delimiter}${originalPath}`;
  t.after(() => { process.env.PATH = originalPath; });
  const options = { dataDir };
  const base = { session_id: 'runner-fixture', turn_id: 'turn', cwd: other };
  const prompt = text => handleHook({ ...base, hook_event_name: 'UserPromptSubmit', prompt: text }, options);
  const pre = (id, name, input) => handleHook({ ...base, hook_event_name: 'PreToolUse', tool_name: name, tool_use_id: id, tool_input: input }, options);
  const input = { command: 'pnpm install --offline --frozen-lockfile --ignore-scripts' };
  prompt('$stop-that-shit change deps=ask -- task');
  const denied = pre('original', 'Bash', input);
  const match = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(denied.hookSpecificOutput.permissionDecisionReason);
  assert.ok(match);
  const question = match[1].replace('<absolute canonical directory>', fs.realpathSync(target));
  assert.equal(pre('question', 'request_user_input_async', { questions: [{ title: question, options: [match[2], match[3]] }] }), null);
  const reply = [{ questionItemId: JSON.stringify(['request_user_input_async', 'question', 0]), question, answer: match[2] }];
  prompt(`<send_user_message_question_reply>\n${JSON.stringify(reply)}\n</send_user_message_question_reply>`);
  const issued = pre('retry', 'Bash', input);
  assert.equal(issued.hookSpecificOutput.permissionDecision, 'allow');
  const bootstrap = issued.hookSpecificOutput.updatedInput.command;
  const duplicate = pre('duplicate', 'Bash', input);
  assert.equal(duplicate.hookSpecificOutput.permissionDecision, 'allow');
  assert.equal(duplicate.hookSpecificOutput.updatedInput.command, bootstrap);
  const shell = process.platform === 'win32' ? 'powershell.exe' : '/bin/sh';
  const shellArgs = process.platform === 'win32' ? ['-NoProfile', '-Command', bootstrap] : ['-c', bootstrap];
  const first = spawnSync(shell, shellArgs, { cwd: other, env: { ...process.env, PLUGIN_DATA: dataDir }, encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr);
  const receipt = JSON.parse(fs.readFileSync(path.join(target, 'receipt.json'), 'utf8'));
  assert.equal(fs.realpathSync(receipt.cwd), fs.realpathSync(target));
  assert.deepEqual(receipt.args, ['install', '--offline', '--frozen-lockfile', '--ignore-scripts']);
  assert.equal(fs.existsSync(path.join(other, 'receipt.json')), false);
  const replay = spawnSync(shell, shellArgs, { cwd: other, env: { ...process.env, PLUGIN_DATA: dataDir }, encoding: 'utf8' });
  assert.notEqual(replay.status, 0);
  assert.match(replay.stderr, /unavailable|expired/);
});

test('approved retry does not resolve its Node bootstrap through PATH', t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sts-node-path-'子' "));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const shimBin = path.join(root, 'shim bin');
  const managerBin = path.join(root, 'manager bin');
  const managerEntry = path.join(managerBin, 'node_modules', 'pnpm', 'bin', 'pnpm.cjs');
  const fakeNode = path.join(shimBin, process.platform === 'win32' ? 'node.exe' : 'node');
  const fakePowerShell = path.join(shimBin, 'powershell.exe');
  const preload = path.join(root, 'path-hit.cjs');
  const marker = path.join(root, 'path-hit');
  fs.mkdirSync(path.dirname(managerEntry), { recursive: true });
  fs.mkdirSync(shimBin, { recursive: true });
  fs.copyFileSync(process.execPath, fakeNode);
  if (process.platform === 'win32') fs.copyFileSync(process.execPath, fakePowerShell);
  if (process.platform !== 'win32') fs.chmodSync(fakeNode, 0o755);
  fs.writeFileSync(managerEntry, 'process.exitCode = 0;');
  fs.writeFileSync(preload, `if ((process.execPath === ${JSON.stringify(fakeNode)} && process.argv[1] === ${JSON.stringify(Buffer.from(path.resolve(__dirname, '../src/dependency-runner.cjs')).toString('base64'))}) || (process.execPath === ${JSON.stringify(fakePowerShell)} && process.argv[1] === '-NoLogo')) require('node:fs').writeFileSync(${JSON.stringify(marker)}, process.execPath);`);

  const previousPath = process.env.PATH;
  const previousNodeOptions = process.env.NODE_OPTIONS;
  process.env.PATH = [shimBin, managerBin, previousPath].filter(Boolean).join(path.delimiter);
  process.env.NODE_OPTIONS = `--require=${JSON.stringify(preload)}`;
  t.after(() => {
    process.env.PATH = previousPath;
    if (previousNodeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = previousNodeOptions;
  });

  const shells = process.platform === 'win32'
    ? [
      [path.join(process.env.SystemRoot || process.env.WINDIR, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), ['-NoProfile', '-Command']],
      [path.join(process.env.SystemRoot || process.env.WINDIR, 'System32', 'cmd.exe'), ['/d', '/s', '/c']]
    ]
    : [['/bin/sh', ['-c']]];
  const target = path.join(root, "approved dir '非ASCII'");
  fs.mkdirSync(target);
  const input = { command: 'pnpm install --offline --frozen-lockfile --ignore-scripts' };
  for (const [index, [shell, prefixArgs]] of shells.entries()) {
    const dataDir = path.join(root, `state-${index}`);
    const options = { dataDir };
    const base = { session_id: `node-path-${index}`, turn_id: 'turn', cwd: root };
    const prompt = text => handleHook({ ...base, hook_event_name: 'UserPromptSubmit', prompt: text }, options);
    const pre = (id, name, toolInput) => handleHook({ ...base, hook_event_name: 'PreToolUse', tool_name: name, tool_use_id: id, tool_input: toolInput }, options);
    prompt('$stop-that-shit change deps=ask -- task');
    const denied = pre('original', 'Bash', input);
    const match = /Approval question: (.+)\nApproval options: (.+) \| (.+)/.exec(denied.hookSpecificOutput.permissionDecisionReason);
    assert.ok(match);
    const question = match[1].replace('<absolute canonical directory>', fs.realpathSync(target));
    assert.equal(pre('question', 'request_user_input_async', { questions: [{ title: question, options: [match[2], match[3]] }] }), null);
    prompt(`<send_user_message_question_reply>\n${JSON.stringify([{ questionItemId: JSON.stringify(['request_user_input_async', 'question', 0]), question, answer: match[2] }])}\n</send_user_message_question_reply>`);
    const issued = pre('retry', 'Bash', input);
    assert.equal(issued.hookSpecificOutput.permissionDecision, 'allow');

    const command = issued.hookSpecificOutput.updatedInput.command;
    const shellArgs = [...prefixArgs, command];
    const result = spawnSync(shell, shellArgs, { cwd: root, env: process.env, encoding: 'utf8' });
    assert.equal(result.status, 0, `${shell}: ${result.stderr}`);
    assert.equal(fs.existsSync(marker), false, `${shell} must not execute the first PATH node shim`);
  }
});

test('runner launcher preserves paths with spaces, apostrophes and non-ASCII characters', t => {
  const { buildRunnerCommand, resolveWindowsPowerShell } = require('../src/runner-command.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sts-launcher-'非ASCII' "));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const executable = path.join(root, `Node '启动'${process.platform === 'win32' ? '.exe' : ''}`);
  const runnerPath = path.join(root, "runner '入口' 子.cjs");
  const dataDir = path.join(root, "批准 '目录' 子");
  const exitDataDir = path.join(root, 'exit-data');
  fs.copyFileSync(process.execPath, executable);
  if (process.platform !== 'win32') fs.chmodSync(executable, 0o755);
  fs.mkdirSync(dataDir);
  fs.mkdirSync(exitDataDir);
  fs.writeFileSync(runnerPath, `module.exports.run = (session, directory, ticket) => { require('node:fs').writeFileSync(require('node:path').join(directory, 'receipt.json'), JSON.stringify({session,directory,ticket})); process.exitCode = session.endsWith('exit23') ? 23 : 0; };`);

  const command = buildRunnerCommand({ executable, runnerPath, sessionId: "session '子", dataDir, ticket: 'a'.repeat(64) });
  const shells = process.platform === 'win32'
    ? [['powershell.exe', ['-NoProfile', '-Command']], ['cmd.exe', ['/d', '/s', '/c']]]
    : [['/bin/sh', ['-c']]];
  for (const [shell, prefixArgs] of shells) {
    const commandForShell = shell === 'powershell.exe' ? `${command}; [Console]::Out.WriteLine($LASTEXITCODE)` : command;
    const result = spawnSync(shell, [...prefixArgs, commandForShell], { cwd: root, env: process.env, encoding: 'utf8' });
    assert.equal(result.status, 0, `${shell}: ${result.stderr}`);
    const failingCommand = buildRunnerCommand({ executable, runnerPath, sessionId: "session 'exit23", dataDir: exitDataDir, ticket: 'b'.repeat(64) });
    const failingCommandForShell = shell === 'powershell.exe' ? `${failingCommand}; [Console]::Out.WriteLine($LASTEXITCODE)` : failingCommand;
    const failed = spawnSync(shell, [...prefixArgs, failingCommandForShell], { cwd: root, env: process.env, encoding: 'utf8' });
    if (shell === 'powershell.exe') assert.match(failed.stdout.trim(), /23$/, 'PowerShell must expose the runner exit code in LASTEXITCODE');
    else assert.equal(failed.status, 23, `${shell} must preserve the runner's exit status: ${failed.stderr}`);
  }
  const receipt = JSON.parse(fs.readFileSync(path.join(dataDir, 'receipt.json'), 'utf8'));
  assert.equal(receipt.session, "session '子");
  assert.equal(receipt.directory, dataDir);
  assert.equal(receipt.ticket, 'a'.repeat(64));

  const systemRootWithSpaces = 'C:\\Program Files\\Windows Root';
  const fullPowerShell = `${systemRootWithSpaces}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
  const shortPowerShell = 'C:\\PROGRA~1\\WINDOW~1\\SYSTEM32\\WINDOW~1\\V1.0\\POWERS~1.EXE';
  const pathMap = new Map([[systemRootWithSpaces, systemRootWithSpaces], [fullPowerShell, fullPowerShell], [shortPowerShell, fullPowerShell]]);
  const fsApi = {
    realpathSync(value) {
      if (!pathMap.has(value)) throw new Error('not found');
      return pathMap.get(value);
    },
    statSync(value) { return { isFile: () => value === fullPowerShell }; }
  };
  assert.equal(resolveWindowsPowerShell({ systemRoot: systemRootWithSpaces, fsApi, shortPath: () => shortPowerShell }), shortPowerShell);
  assert.throws(() => resolveWindowsPowerShell({ systemRoot: systemRootWithSpaces, fsApi, shortPath: () => fullPowerShell }), /no usable short path/i);
  if (process.platform === 'win32') {
    const launcher = resolveWindowsPowerShell({ shortPath: () => { throw new Error('standard path must not request a short path'); } });
    assert.match(launcher, /^[A-Za-z]:\\/);
  }
});

test('runner rejects an executable changed after approval without starting it', t => {
  const { fingerprint } = require('../src/dependency-manager.cjs');
  const { freshState, writeState } = require('../src/state.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-manager-change-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cwd = fs.realpathSync(root);
  const entry = path.join(root, 'manager.cjs');
  const marker = path.join(root, 'marker');
  fs.writeFileSync(entry, `require('node:fs').writeFileSync(${JSON.stringify(marker)},'run')`);
  const manager = { kind: 'node', entry: fingerprint(entry), executable: fingerprint(process.execPath) };
  const state = freshState();
  state.contract = { ...state.contract, mode: 'change', level: 'guard', dependencyPolicy: 'ask' };
  state.actionApproval = { digest: 'a'.repeat(64), eventId: 'evt_00000000-0000-0000-0000-000000000000',
    questionPrefix: 'prefix', question: 'question', questionId: 'id', questionCallId: 'q', deniedActionId: 'a',
    expires: Date.now() + 30000, proposalExpires: Date.now() + 30000, status: 'issued', requestedCwd: cwd, targetCwd: cwd, ticket: 'a'.repeat(64), argv: ['pnpm', 'install'], manager, approvedAction: { mutability: 'write', hashIntent: false, affectedPaths: [], cwd } };
  writeState('changed', state, root);
  fs.appendFileSync(entry, '\n// changed');
  const result = spawnSync(process.execPath, [path.join(__dirname, '../src/dependency-runner.cjs'), 'changed', root, 'a'.repeat(64)], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /package manager changed/);
  assert.equal(fs.existsSync(marker), false);
});

test('child exit status and audit failure remain visible and ticket cannot replay', t => {
  const { fingerprint } = require('../src/dependency-manager.cjs');
  const { freshState, writeState } = require('../src/state.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-runner-exit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const entry = path.join(root, 'manager.cjs');
  fs.writeFileSync(entry, 'process.exitCode = 23;');
  fs.writeFileSync(path.join(root, 'runtime'), 'not a directory');
  const state = freshState();
  state.contract = { ...state.contract, mode: 'change', level: 'guard', dependencyPolicy: 'ask' };
  state.actionApproval = { digest: 'a'.repeat(64), eventId: 'evt_00000000-0000-0000-0000-000000000000',
    questionPrefix: 'prefix', question: 'question', questionId: 'id', questionCallId: 'q', deniedActionId: 'a',
    expires: Date.now() + 30000, proposalExpires: Date.now() + 30000, status: 'issued', requestedCwd: fs.realpathSync(root), targetCwd: fs.realpathSync(root), ticket: 'b'.repeat(64),
    argv: ['pnpm', 'install'], manager: { kind: 'node', entry: fingerprint(entry), executable: fingerprint(process.execPath) },
    approvedAction: { mutability: 'write', hashIntent: false, affectedPaths: [], cwd: fs.realpathSync(root) } };
  writeState('exit-test', state, root);
  const args = [path.join(__dirname, '../src/dependency-runner.cjs'), 'exit-test', root, 'b'.repeat(64)];
  const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(first.status, 23);
  assert.match(first.stderr, /audit unavailable/);
  const replay = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.notEqual(replay.status, 0);
  assert.match(replay.stderr, /unavailable|expired/);
});

test('a failed native executable launch consumes the ticket and reports an error', t => {
  const { fingerprint } = require('../src/dependency-manager.cjs');
  const { freshState, writeState } = require('../src/state.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-runner-error-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const entry = path.join(root, 'invalid.exe');
  fs.writeFileSync(entry, 'not an executable');
  const state = freshState();
  state.contract = { ...state.contract, mode: 'change', level: 'guard', dependencyPolicy: 'ask' };
  state.actionApproval = { digest: 'a'.repeat(64), eventId: 'evt_00000000-0000-0000-0000-000000000000',
    questionPrefix: 'prefix', question: 'question', questionId: 'id', questionCallId: 'q', deniedActionId: 'a',
    expires: Date.now() + 30000, proposalExpires: Date.now() + 30000, status: 'issued', requestedCwd: fs.realpathSync(root), targetCwd: fs.realpathSync(root), ticket: 'c'.repeat(64),
    argv: ['pnpm', 'install'], manager: { kind: 'native', entry: fingerprint(entry), launchPath: entry },
    approvedAction: { mutability: 'write', hashIntent: false, affectedPaths: [], cwd: fs.realpathSync(root) } };
  writeState('error-test', state, root);
  const args = [path.join(__dirname, '../src/dependency-runner.cjs'), 'error-test', root, 'c'.repeat(64)];
  const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.notEqual(first.status, 0);
  assert.match(first.stderr, /controlled dependency operation failed/);
  const replay = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.notEqual(replay.status, 0);
  assert.match(replay.stderr, /unavailable|expired/);
});

test('runner rechecks tightened file and hash gates before consuming a ticket', t => {
  const { fingerprint } = require('../src/dependency-manager.cjs');
  const { freshState, readState, writeState } = require('../src/state.cjs');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sts-tightened-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const entry = path.join(root, 'manager.cjs');
  const marker = path.join(root, 'marker');
  fs.writeFileSync(entry, `require('node:fs').writeFileSync(${JSON.stringify(marker)},'run')`);
  const manager = { kind: 'node', entry: fingerprint(entry), executable: fingerprint(process.execPath) };
  for (const [session, contractChange] of [['files', { allowedPaths: ['src/**'], hashPolicy: 'allow' }], ['hash', { allowedPaths: null, hashPolicy: 'deny' }]]) {
    const state = freshState();
    state.contract = { ...state.contract, mode: 'change', level: 'guard', dependencyPolicy: 'ask', ...contractChange };
    state.actionApproval = { digest: 'a'.repeat(64), eventId: 'evt_00000000-0000-0000-0000-000000000000',
      questionPrefix: 'prefix', question: 'question', questionId: 'id', questionCallId: 'q', deniedActionId: 'a',
      expires: Date.now() + 30000, proposalExpires: Date.now() + 30000, status: 'issued', requestedCwd: fs.realpathSync(root), targetCwd: fs.realpathSync(root), ticket: 'd'.repeat(64),
      argv: ['pnpm', 'install'], manager, approvedAction: { mutability: 'write', hashIntent: true, affectedPaths: [], cwd: fs.realpathSync(root) } };
    writeState(session, state, root);
    const result = spawnSync(process.execPath, [path.join(__dirname, '../src/dependency-runner.cjs'), session, root, 'd'.repeat(64)], { encoding: 'utf8' });
    assert.notEqual(result.status, 0, session);
    assert.equal(readState(session, root).actionApproval.status, 'issued', session);
    assert.equal(fs.existsSync(marker), false, session);
  }
});
