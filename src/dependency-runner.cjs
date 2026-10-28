'use strict';

const fs = require('node:fs');
const { spawn } = require('node:child_process');
const { updateSession } = require('./state.cjs');
const { live } = require('./action-approval.cjs');
const { unchanged } = require('./dependency-manager.cjs');
const { recordDecision } = require('./runtime-audit.cjs');
const { decide } = require('./decision.cjs');
const { inspectDelegation } = require('./delegation-state.cjs');

function claim(sessionId, dataDir, ticket) {
  return updateSession(sessionId, dataDir, state => {
    const record = state.actionApproval;
    if (state.storageError || !live(record) || record.status !== 'issued' || record.ticket !== ticket
        || state.contract.mode !== 'change' || state.contract.level !== 'guard'
        || state.contract.dependencyPolicy !== 'ask') throw new Error('Approval is unavailable or expired');
    if (!record.requestedCwd || !record.targetCwd || fs.realpathSync(record.requestedCwd) !== record.targetCwd
        || fs.realpathSync(record.targetCwd) !== record.targetCwd || !fs.statSync(record.targetCwd).isDirectory()) throw new Error('Approved directory changed');
    if (!unchanged(record.manager.entry)
        || record.manager.kind === 'native' && (!record.manager.launchPath || fs.realpathSync(record.manager.launchPath) !== record.manager.entry.path)
        || record.manager.kind === 'node' && !unchanged(record.manager.executable)) throw new Error('Approved package manager changed');
    if (!record.approvedAction || typeof record.approvedAction !== 'object') throw new Error('Approved action facts unavailable');
    const action = { ...record.approvedAction, cwd: record.targetCwd, dependencyIntent: false };
    const decision = decide({ contract: state.contract, action, delegation: inspectDelegation(state.delegation), state });
    if (decision.outcome !== 'allow') throw new Error(`Approved operation no longer satisfies current policy: ${decision.reasonCode}`);
    record.status = 'consumed';
    delete record.ticket;
    try {
      const audit = recordDecision({ sessionId, contract: state.contract, delegation: state.delegation,
        action: { name: 'dependency-runner', mutability: 'write', dependencyIntent: true },
        decision: { outcome: 'allow', reasonCode: 'WITHIN_CONTRACT' }, responseOutcome: 'none',
        approval: { eventId: record.eventId, questionCallId: record.questionCallId, consumed: true } }, { dataDir });
      if (!audit) process.stderr.write('Stop That Shit: approval audit unavailable.\n');
    } catch {
      process.stderr.write('Stop That Shit: approval audit unavailable.\n');
    }
    return { cwd: record.targetCwd, manager: record.manager, args: record.argv.slice(1) };
  });
}

function main(sessionId, dataDir, ticket) {
  if (!sessionId || !dataDir || !/^[a-f0-9]{64}$/.test(ticket || '')) throw new Error('Invalid approval ticket');
  const operation = claim(sessionId, dataDir, ticket);
  const executable = operation.manager.kind === 'node' ? operation.manager.executable.path : operation.manager.launchPath;
  const args = operation.manager.kind === 'node' ? [operation.manager.entry.path, ...operation.args] : operation.args;
  const child = spawn(executable, args, { cwd: operation.cwd, shell: false, stdio: 'inherit' });
  const forwardInterrupt = () => child.kill('SIGINT');
  const forwardTermination = () => child.kill('SIGTERM');
  process.on('SIGINT', forwardInterrupt);
  process.on('SIGTERM', forwardTermination);
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      process.off('SIGINT', forwardInterrupt);
      process.off('SIGTERM', forwardTermination);
    };
    child.once('error', error => { cleanup(); reject(error); });
    child.once('exit', (status, signal) => {
      cleanup();
      resolve(Number.isInteger(status) ? status : signal === 'SIGINT' ? 130 : 1);
    });
  });
}

async function run(sessionId, dataDir, ticket) {
  try { process.exitCode = await main(sessionId, dataDir, ticket); }
  catch (error) { process.stderr.write(`Stop That Shit: controlled dependency operation failed: ${error.message}\n`); process.exitCode = 1; }
}

if (require.main === module) run(...process.argv.slice(2));
module.exports = { run };
